/**
 * @file pcapparser.h
 * @author James Mathewson
 * @version 1.1.0 beta (String Support)
 * @brief Defines the AST nodes and parser.
 */
#ifndef __pcap_abbv_parser_h__
#define __pcap_abbv_parser_h__

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <stdexcept>
#include <cctype>
#include <utility>
#include <string_view> // <-- NEW
#include <sstream>
#include <numeric>
#include <deque>

namespace pcapabvparser {

// Token types
enum class TokenType { IDENT, NUMBER, STRING, OP, LPAREN, RPAREN, COMMA, END }; // Added STRING

// Token structure
struct Token {
    TokenType type;
    std::string value;
};

// Tokenizer
class Tokenizer {
public:
    Tokenizer(const std::string& str);
    Token next();

private:
    std::string input;
    size_t pos;
    Token current;
};

// AST Node
struct ASTNode {
    virtual int eval() const = 0;
    virtual ~ASTNode() = default;
    virtual std::unique_ptr<ASTNode> clone() const = 0;
};

using ASTPtr = std::unique_ptr<ASTNode>;

void getFnNames(const ASTNode* node, std::vector<std::string>& names);

using Func = std::function<int(const std::vector<int>&)>;
using StringFunc = std::function<std::string_view(const std::vector<int>&)>; // <-- NEW

// --- Existing Nodes (FuncCallNode, ConstNode, UnaryNode, BinaryNode) ---
// (Declarations only, implementation in .cpp)

struct FuncCallNode : ASTNode {
    std::string name;
    std::vector<ASTPtr> args;
    Func* m_bound_function_ptr = nullptr;

    FuncCallNode(std::string n, std::vector<ASTPtr> a);
    int eval() const override;
    std::unique_ptr<ASTNode> clone() const override;
};

struct ConstNode : ASTNode {
    int value;
    ConstNode(int v);
    int eval() const override;
    std::unique_ptr<ASTNode> clone() const override;
};

struct UnaryNode : ASTNode {
    std::string op;
    ASTPtr operand;
    UnaryNode(std::string o, ASTPtr e);
    int eval() const override;
    std::unique_ptr<ASTNode> clone() const override;
};

struct BinaryNode : ASTNode {
    ASTPtr left;
    std::string op;
    ASTPtr right;
    BinaryNode(ASTPtr l, std::string o, ASTPtr r);
    int eval() const override;
    std::unique_ptr<ASTNode> clone() const override;
};

// --- NEW: String Comparison Node ---
/**
 * @brief specialized node for comparing a packet string field against a literal.
 * Example: TLS.Sni() == "google.com"
 */
struct StringCompareNode : ASTNode {
    std::string funcName;       // e.g., "TLS.Sni"
    std::vector<ASTPtr> args;   // e.g., index 1
    std::string op;             // "==", "!="
    std::string target;         // "google.com"

    // The bound zero-copy string extractor
    StringFunc* m_bound_string_func = nullptr;

    StringCompareNode(std::string name, std::vector<ASTPtr> a, std::string o, std::string t);

    int eval() const override; // Returns 1 (true) or 0 (false)

    std::unique_ptr<ASTNode> clone() const override;
};

// Parser
class FnParser {
public:
    FnParser(const std::string& input);
    ASTPtr parse();

private:
    Tokenizer tokenizer;
    Token current;

    void advance();
    ASTPtr parsePrimary();
    ASTPtr parseComparison();
    ASTPtr parseAnd();
    ASTPtr parseOr();
    ASTPtr parseExpression();
};

} // namespace pcapabvparser
#endif // __pcap_abbv_parser_h__
