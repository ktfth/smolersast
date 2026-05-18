using SmolerSAST.Core.Indexing;
using SmolerSAST.Core.Tests.Helpers;

namespace SmolerSAST.Core.Tests.Indexing;

public sealed class InMemorySymbolIndexTests
{
    [Fact]
    public async Task IndexAsync_IndexesTypesAndMembers()
    {
        const string source = """
            namespace TestNamespace
            {
                public class MyService
                {
                    public string Name { get; }
                    public void DoWork() { }
                }
            }
            """;

        var compilation = CompilationHelper.CreateCompilation(source);
        var index = new InMemorySymbolIndex();

        await index.IndexAsync(compilation);

        Assert.True(index.Count > 0);

        var typeEntries = index.Lookup("TestNamespace.MyService");
        Assert.NotEmpty(typeEntries);
        Assert.Equal(SymbolEntryKind.Type, typeEntries[0].Kind);
    }

    [Fact]
    public async Task Lookup_UnknownSymbol_ReturnsEmpty()
    {
        const string source = "namespace Test { public class Foo { } }";
        var compilation = CompilationHelper.CreateCompilation(source);
        var index = new InMemorySymbolIndex();

        await index.IndexAsync(compilation);

        var entries = index.Lookup("NonExistent.Type");
        Assert.Empty(entries);
    }

    [Fact]
    public void Lookup_Null_ThrowsArgumentNull()
    {
        var index = new InMemorySymbolIndex();
        Assert.Throws<ArgumentNullException>(() => index.Lookup(null!));
    }

    [Fact]
    public async Task IndexAsync_Null_ThrowsArgumentNull()
    {
        var index = new InMemorySymbolIndex();
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            index.IndexAsync(null!));
    }
}
