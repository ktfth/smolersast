using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace SmolerSAST.Core.Taint;

/// <summary>
/// Performs intraprocedural taint analysis within a single method body.
/// Tracks taint from sources through assignments and expressions to sinks.
/// </summary>
public sealed class IntraproceduralTaintAnalyzer
{
    private readonly TaintSourceRegistry _sources;
    private readonly TaintSinkRegistry _sinks;
    private readonly TaintSanitizerRegistry _sanitizers;

    public IntraproceduralTaintAnalyzer(
        TaintSourceRegistry sources,
        TaintSinkRegistry sinks,
        TaintSanitizerRegistry sanitizers)
    {
        _sources = sources;
        _sinks = sinks;
        _sanitizers = sanitizers;
    }

    /// <summary>
    /// Analyzes a method body for taint flows from source to sink.
    /// </summary>
    public ImmutableArray<TaintFlow> AnalyzeMethod(
        MethodDeclarationSyntax method,
        SemanticModel semanticModel)
    {
        if (method.Body is null && method.ExpressionBody is null)
            return [];

        var taintState = new Dictionary<string, TaintedValue>(StringComparer.Ordinal);
        var flows = ImmutableArray.CreateBuilder<TaintFlow>();
        var filePath = method.SyntaxTree.FilePath ?? "Unknown";

        // Step 1: Mark tainted parameters
        foreach (var param in method.ParameterList.Parameters)
        {
            var paramName = param.Identifier.Text;
            var paramType = param.Type?.ToString() ?? "";

            if (_sources.IsParameterTypeSource(paramType, out var label))
            {
                var location = CreateLocation(param, filePath, $"Parameter '{paramName}' of type {paramType}");
                taintState[paramName] = new TaintedValue(paramName, label, location, []);
            }

            // Check if parameter has [FromQuery], [FromBody], [FromForm], [FromRoute]
            var attrs = param.AttributeLists.SelectMany(a => a.Attributes).Select(a => a.Name.ToString());
            if (attrs.Any(a => a.StartsWith("From", StringComparison.Ordinal)))
            {
                var location = CreateLocation(param, filePath, $"Parameter '{paramName}' from HTTP request");
                taintState[paramName] = new TaintedValue(paramName, TaintLabel.UserInput, location, []);
            }
        }

        // Step 2: Walk statements in order
        var statements = method.Body?.Statements
            ?? (method.ExpressionBody is not null
                ? [SyntaxFactory.ExpressionStatement(method.ExpressionBody.Expression)]
                : (SyntaxList<StatementSyntax>)[]);

        foreach (var statement in statements)
        {
            AnalyzeStatement(statement, semanticModel, taintState, flows, filePath);
        }

        return flows.ToImmutable();
    }

    private void AnalyzeStatement(
        StatementSyntax statement,
        SemanticModel semanticModel,
        Dictionary<string, TaintedValue> taintState,
        ImmutableArray<TaintFlow>.Builder flows,
        string filePath)
    {
        switch (statement)
        {
            case LocalDeclarationStatementSyntax localDecl:
                AnalyzeLocalDeclaration(localDecl, semanticModel, taintState, flows, filePath);
                break;

            case ExpressionStatementSyntax exprStmt:
                AnalyzeExpression(exprStmt.Expression, semanticModel, taintState, flows, filePath);
                break;

            case ReturnStatementSyntax returnStmt when returnStmt.Expression is not null:
                CheckSinkUsage(returnStmt.Expression, semanticModel, taintState, flows, filePath);
                break;

            case IfStatementSyntax ifStmt:
                if (ifStmt.Statement is BlockSyntax ifBlock)
                    foreach (var s in ifBlock.Statements)
                        AnalyzeStatement(s, semanticModel, taintState, flows, filePath);
                if (ifStmt.Else?.Statement is BlockSyntax elseBlock)
                    foreach (var s in elseBlock.Statements)
                        AnalyzeStatement(s, semanticModel, taintState, flows, filePath);
                break;

            case BlockSyntax block:
                foreach (var s in block.Statements)
                    AnalyzeStatement(s, semanticModel, taintState, flows, filePath);
                break;
        }
    }

    private void AnalyzeLocalDeclaration(
        LocalDeclarationStatementSyntax localDecl,
        SemanticModel semanticModel,
        Dictionary<string, TaintedValue> taintState,
        ImmutableArray<TaintFlow>.Builder flows,
        string filePath)
    {
        foreach (var variable in localDecl.Declaration.Variables)
        {
            if (variable.Initializer?.Value is not { } initializer) continue;

            var varName = variable.Identifier.Text;

            // Check if initializer is a taint source
            var tainted = GetTaintFromExpression(initializer, semanticModel, taintState, filePath);
            if (tainted is not null)
            {
                var step = CreateLocation(variable, filePath, $"Assigned to '{varName}'");
                taintState[varName] = tainted.WithStep(step);
            }

            // Check if initializer calls a sink with tainted args
            CheckSinkUsage(initializer, semanticModel, taintState, flows, filePath);
        }
    }

    private void AnalyzeExpression(
        ExpressionSyntax expression,
        SemanticModel semanticModel,
        Dictionary<string, TaintedValue> taintState,
        ImmutableArray<TaintFlow>.Builder flows,
        string filePath)
    {
        switch (expression)
        {
            case AssignmentExpressionSyntax assignment:
            {
                var targetName = assignment.Left.ToString();
                var tainted = GetTaintFromExpression(assignment.Right, semanticModel, taintState, filePath);
                if (tainted is not null)
                {
                    var step = CreateLocation(assignment, filePath, $"Assigned to '{targetName}'");
                    taintState[targetName] = tainted.WithStep(step);
                }
                CheckSinkUsage(assignment.Right, semanticModel, taintState, flows, filePath);
                break;
            }

            case InvocationExpressionSyntax invocation:
                CheckSinkUsage(invocation, semanticModel, taintState, flows, filePath);
                break;
        }
    }

    private TaintedValue? GetTaintFromExpression(
        ExpressionSyntax expression,
        SemanticModel semanticModel,
        Dictionary<string, TaintedValue> taintState,
        string filePath)
    {
        switch (expression)
        {
            // Direct variable reference
            case IdentifierNameSyntax identifier:
                return taintState.GetValueOrDefault(identifier.Identifier.Text);

            // Member access (e.g., request.Query, dto.Name)
            case MemberAccessExpressionSyntax memberAccess:
            {
                var memberName = memberAccess.Name.Identifier.Text;
                var receiverName = memberAccess.Expression.ToString();

                // Check if the member itself is a taint source
                if (_sources.IsSource(memberName, out var label))
                {
                    var location = CreateLocation(memberAccess, filePath, $"Source: {receiverName}.{memberName}");
                    return new TaintedValue(memberName, label, location, []);
                }

                // Check if receiver is tainted (propagation)
                if (taintState.TryGetValue(receiverName, out var receiverTaint))
                {
                    var step = CreateLocation(memberAccess, filePath, $"Accessed .{memberName} on tainted '{receiverName}'");
                    return receiverTaint.WithStep(step);
                }

                return null;
            }

            // Method call (e.g., File.ReadAllText(...))
            case InvocationExpressionSyntax invocation:
            {
                var methodName = invocation.Expression switch
                {
                    MemberAccessExpressionSyntax ma => ma.Name.Identifier.Text,
                    IdentifierNameSyntax id => id.Identifier.Text,
                    _ => null,
                };

                if (methodName is null) return null;

                // Check if this method call is a sanitizer — if so, it removes taint
                if (_sanitizers.IsSanitizer(methodName)) return null;

                // Check if return value is a taint source
                if (_sources.IsSource(methodName, out var label))
                {
                    var location = CreateLocation(invocation, filePath, $"Source: {methodName}()");
                    return new TaintedValue(methodName, label, location, []);
                }

                // Check if receiver is tainted (e.g., input.Trim(), taintedStr.ToLower())
                if (invocation.Expression is MemberAccessExpressionSyntax receiverAccess)
                {
                    var receiverTaint = GetTaintFromExpression(receiverAccess.Expression, semanticModel, taintState, filePath);
                    if (receiverTaint is not null)
                    {
                        var step = CreateLocation(invocation, filePath, $"Passed through .{methodName}()");
                        return receiverTaint.WithStep(step);
                    }
                }

                // If any argument is tainted and method is not a sanitizer, propagate taint
                foreach (var arg in invocation.ArgumentList.Arguments)
                {
                    var argTaint = GetTaintFromExpression(arg.Expression, semanticModel, taintState, filePath);
                    if (argTaint is not null)
                    {
                        var step = CreateLocation(invocation, filePath, $"Passed through {methodName}()");
                        return argTaint.WithStep(step);
                    }
                }

                return null;
            }

            // String concatenation propagates taint
            case BinaryExpressionSyntax binary when binary.IsKind(SyntaxKind.AddExpression):
            {
                var leftTaint = GetTaintFromExpression(binary.Left, semanticModel, taintState, filePath);
                if (leftTaint is not null) return leftTaint;
                return GetTaintFromExpression(binary.Right, semanticModel, taintState, filePath);
            }

            // String interpolation propagates taint
            case InterpolatedStringExpressionSyntax interpolated:
            {
                foreach (var content in interpolated.Contents)
                {
                    if (content is InterpolationSyntax interp)
                    {
                        var taint = GetTaintFromExpression(interp.Expression, semanticModel, taintState, filePath);
                        if (taint is not null) return taint;
                    }
                }
                return null;
            }

            // Conditional expressions propagate taint from either branch
            case ConditionalExpressionSyntax conditional:
            {
                return GetTaintFromExpression(conditional.WhenTrue, semanticModel, taintState, filePath)
                    ?? GetTaintFromExpression(conditional.WhenFalse, semanticModel, taintState, filePath);
            }

            default:
                return null;
        }
    }

    private void CheckSinkUsage(
        ExpressionSyntax expression,
        SemanticModel semanticModel,
        Dictionary<string, TaintedValue> taintState,
        ImmutableArray<TaintFlow>.Builder flows,
        string filePath)
    {
        if (expression is not InvocationExpressionSyntax invocation) return;

        var methodName = invocation.Expression switch
        {
            MemberAccessExpressionSyntax ma => ma.Name.Identifier.Text,
            IdentifierNameSyntax id => id.Identifier.Text,
            _ => null,
        };

        if (methodName is null) return;

        // Check if this is a sanitizer — if so, skip
        if (_sanitizers.IsSanitizer(methodName)) return;

        // Check if this method is a sink
        if (!_sinks.IsSink(methodName, out var sinkDescriptor)) return;

        TaintedValue? foundTaint = null;

        // Check if any argument flowing into the sink is tainted
        for (var i = 0; i < invocation.ArgumentList.Arguments.Count; i++)
        {
            var arg = invocation.ArgumentList.Arguments[i];
            foundTaint = GetTaintFromExpression(arg.Expression, semanticModel, taintState, filePath);
            if (foundTaint is not null) break;
        }

        // If no tainted args, check if the receiver object has tainted properties
        // (e.g., cmd.CommandText was set to tainted value, then cmd.ExecuteNonQuery() is called)
        if (foundTaint is null && invocation.Expression is MemberAccessExpressionSyntax memberAccess)
        {
            var receiverName = memberAccess.Expression.ToString();

            // Check if receiver.CommandText, receiver.CommandText, etc. was set to tainted value
            var taintedProps = new[] { "CommandText", "InnerText", "InnerHtml", "Text", "Value", "Filter" };
            foreach (var prop in taintedProps)
            {
                var key = $"{receiverName}.{prop}";
                if (taintState.TryGetValue(key, out var propTaint))
                {
                    foundTaint = propTaint;
                    break;
                }
            }

            // Also check if receiver itself is tainted
            if (foundTaint is null)
            {
                foundTaint = taintState.GetValueOrDefault(receiverName);
            }
        }

        if (foundTaint is not null)
        {
            var sinkLocation = CreateLocation(invocation, filePath, $"Sink: {methodName}()");
            var confidence = foundTaint.PropagationPath.Length switch
            {
                0 => 0.95,   // Direct source → sink
                1 => 0.90,   // One step
                2 => 0.85,   // Two steps
                _ => 0.75,   // Longer paths are less confident
            };

            flows.Add(new TaintFlow(foundTaint, sinkLocation, sinkDescriptor, confidence));
        }

        // Recurse into nested invocations within arguments
        foreach (var arg in invocation.ArgumentList.Arguments)
        {
            CheckSinkUsage(arg.Expression, semanticModel, taintState, flows, filePath);
        }
    }

    private static TaintLocation CreateLocation(SyntaxNode node, string filePath, string description)
    {
        var lineSpan = node.GetLocation().GetLineSpan();
        return new TaintLocation(
            filePath,
            lineSpan.StartLinePosition.Line + 1,
            lineSpan.StartLinePosition.Character,
            description);
    }
}
