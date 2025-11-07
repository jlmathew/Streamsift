/**
 * @file pcapparser.h
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
#include <sstream> // For Tokenizer
#include <numeric> // For ASTNode::clone
#include <deque> // For ASTNode::clone

namespace pcapabvparser {

// Token types
enum class TokenType { IDENT, NUMBER, OP, LPAREN, RPAREN, COMMA, END };

// Token structure
struct Token {
    TokenType type;
    std::string value;
};

// Tokenizer
class Tokenizer {
public:
    Tokenizer(const std::string& str); // <-- FIX: Removed inline definition
    Token next();

private:
    std::string input;
    size_t pos;
    Token current; // <-- FIX: Added this member
};

// AST Node
struct ASTNode {
    virtual int eval() const = 0;
    virtual ~ASTNode() = default;
    
    /**
     * @brief Clones the AST node.
     * @return A unique_ptr to the new, cloned ASTNode.
     */
    virtual std::unique_ptr<ASTNode> clone() const = 0;
};

using ASTPtr = std::unique_ptr<ASTNode>;

/**
 * @brief Traverses the AST and collects all function call names.
 * @param node The current AST node.
 * @param names A reference to the vector to store the names.
 */
void getFnNames(const ASTNode* node, std::vector<std::string>& names);

using Func = std::function<int(const std::vector<int>&)>;

/**
 * @struct FuncCallNode
 * @brief AST node for a function call.
 *
 * This node has been modified for "AST Binding". It holds a
 * raw pointer (m_bound_function_ptr) to the std::function it
 * will call. This pointer is set *once* when the stream is
 * created, eliminating all map lookups from the eval() path.
 */
struct FuncCallNode : ASTNode {
    std::string name;
    std::vector<ASTPtr> args;
    
    /**
     * @brief A direct, "bound" pointer to the std::function this node calls.
     *
     * This pointer points to a std::function living inside a
     * protoTrigger object (e.g., protoTcpTrigger::m_protoMap).
     * It is safe because this AST is owned by the same PacketStreamEval
     * that owns the protoTrigger.
     */
    Func* m_bound_function_ptr = nullptr; // The "linked" function

    FuncCallNode(std::string n, std::vector<ASTPtr> a);
    int eval() const override;
    
    /**
     * @brief Clones the AST node and its children.
     * @return A unique_ptr to the new ASTNode.
     */
    std::unique_ptr<ASTNode> clone() const override {
        std::vector<ASTPtr> cloned_args;
        for(const auto& arg : args) {
            cloned_args.push_back(std::unique_ptr<ASTNode>(arg->clone()));
        }
        // Note: m_bound_function_ptr is NOT cloned.
        // It must be set by the new owner.
        return std::make_unique<FuncCallNode>(name, std::move(cloned_args));
    }
};

// Constant node
struct ConstNode : ASTNode {
    int value;
    ConstNode(int v); // <-- FIX: Removed inline definition
    int eval() const override;
    
    std::unique_ptr<ASTNode> clone() const override {
        return std::make_unique<ConstNode>(value);
    }
};

// Unary node
struct UnaryNode : ASTNode {
    std::string op;
    ASTPtr operand;
    UnaryNode(std::string o, ASTPtr e); // <-- FIX: Removed inline definition
    int eval() const override;
    
    std::unique_ptr<ASTNode> clone() const override {
        return std::make_unique<UnaryNode>(op, std::unique_ptr<ASTNode>(operand->clone()));
    }
};

// Binary node
struct BinaryNode : ASTNode {
    ASTPtr left;
    std::string op;
    ASTPtr right;
    BinaryNode(ASTPtr l, std::string o, ASTPtr r); // <-- FIX: Removed inline definition
    int eval() const override;
    
    std::unique_ptr<ASTNode> clone() const override {
        return std::make_unique<BinaryNode>(
            std::unique_ptr<ASTNode>(left->clone()),
            op,
            std::unique_ptr<ASTNode>(right->clone())
        );
    }
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