/**
 * @file pcapparser.cpp
 * @author James Mathewson
 * @version 1.1.0 beta (String Support)
 * @brief Implementation of the AST parser and nodes.
 */

#include "pcapparser.h"
#include <stdexcept>
#include <cctype>
#include <utility>
#include <thread>
#include <iostream>
#include <cstring>

namespace pcapabvparser
{

// ... (getFnNames helper same as before) ...
void getFnNames(const ASTNode* node, std::vector<std::string>& names) {
    if (!node) return;
    if (const auto* func = dynamic_cast<const FuncCallNode*>(node)) {
        names.push_back(func->name);
        for (const auto& arg : func->args) getFnNames(arg.get(), names);
    } else if (const auto* unary = dynamic_cast<const UnaryNode*>(node)) {
        getFnNames(unary->operand.get(), names);
    } else if (const auto* binary = dynamic_cast<const BinaryNode*>(node)) {
        getFnNames(binary->left.get(), names);
        getFnNames(binary->right.get(), names);
    } else if (const auto* strNode = dynamic_cast<const StringCompareNode*>(node)) {
        // StringCompareNode ALSO holds a function name internally
        names.push_back(strNode->funcName);
    }
}

// Tokenizer
Tokenizer::Tokenizer(const std::string& str) : input(str), pos(0), current{TokenType::END, ""} {}

Token Tokenizer::next()
{
    while (pos < input.size() && isspace(input[pos])) ++pos;
    if (pos >= input.size()) return {TokenType::END, ""};

    char ch = input[pos];

    // --- NEW: Handle Quoted Strings ---
    if (ch == '"') {
        size_t start = ++pos;
        std::string val;
        while (pos < input.size() && input[pos] != '"') {
            // Handle basic escaping if needed, for now simple strings
            val += input[pos++];
        }
        if (pos >= input.size()) throw std::runtime_error("Unterminated string literal");
        ++pos; // Skip closing quote
        return {TokenType::STRING, val};
    }
    // ----------------------------------

    if (isdigit(ch) || (ch == '-' && pos + 1 < input.size() && isdigit(input[pos + 1])))
    {
        size_t start = pos;
        if (input[pos] == '-') ++pos;
        while (pos < input.size() && isdigit(input[pos])) ++pos;
        return {TokenType::NUMBER, input.substr(start, pos - start)};
    }

    if (isalpha(ch))
    {
        size_t start = pos;
        while (pos < input.size() && (isalnum(input[pos]) || input[pos] == '.')) ++pos;
        std::string word = input.substr(start, pos - start);
        if (word == "AND" || word == "OR") return {TokenType::OP, word};
        return {TokenType::IDENT, word};
    }

    if (ch == '(') return ++pos, Token{TokenType::LPAREN, "("};
    if (ch == ')') return ++pos, Token{TokenType::RPAREN, ")"};
    if (ch == ',') return ++pos, Token{TokenType::COMMA, ","};

    if (ch == '=' || ch == '!' || ch == '<' || ch == '>')
    {
        std::string op(1, ch);
        ++pos;
        if (pos < input.size() && input[pos] == '=')
        {
            op += input[pos++];
        }
        return {TokenType::OP, op};
    }

    throw std::runtime_error("Unknown character: " + std::string(1, ch));
}

// ... (FuncCallNode, ConstNode, UnaryNode, BinaryNode same as before) ...
// (Omitting for brevity, they are unchanged from v0.9.17)
FuncCallNode::FuncCallNode(std::string n, std::vector<ASTPtr> a) : name(std::move(n)), args(std::move(a)), m_bound_function_ptr(nullptr) {}
int FuncCallNode::eval() const {
    std::vector<int> evaluatedArgs;
    for (const auto& arg : args) evaluatedArgs.push_back(arg->eval());
    if (!m_bound_function_ptr) throw std::runtime_error("Function '" + name + "' unbound.");
    return (*m_bound_function_ptr)(evaluatedArgs);
}
std::unique_ptr<ASTNode> FuncCallNode::clone() const {
    std::vector<ASTPtr> c_args; for(auto& a:args) c_args.push_back(a->clone());
    return std::make_unique<FuncCallNode>(name, std::move(c_args));
}

ConstNode::ConstNode(int v) : value(v) {}
int ConstNode::eval() const { return value; }
std::unique_ptr<ASTNode> ConstNode::clone() const { return std::make_unique<ConstNode>(value); }

UnaryNode::UnaryNode(std::string o, ASTPtr e) : op(std::move(o)), operand(std::move(e)) {}
int UnaryNode::eval() const { if (op == "!") return !operand->eval(); throw std::runtime_error("Unknown unary op"); }
std::unique_ptr<ASTNode> UnaryNode::clone() const { return std::make_unique<UnaryNode>(op, operand->clone()); }

BinaryNode::BinaryNode(ASTPtr l, std::string o, ASTPtr r) : left(std::move(l)), op(std::move(o)), right(std::move(r)) {}
int BinaryNode::eval() const {
    int l = left->eval(), r = right->eval();
    if (op == "AND") return l && r;
    if (op == "OR") return l || r;
    if (op == ">") return l > r;
    if (op == "<") return l < r;
    if (op == ">=") return l >= r;
    if (op == "<=") return l <= r;
    if (op == "==") return l == r;
    if (op == "!=") return l != r;
    throw std::runtime_error("Unknown binary op");
}
std::unique_ptr<ASTNode> BinaryNode::clone() const { return std::make_unique<BinaryNode>(left->clone(), op, right->clone()); }


// --- NEW: StringCompareNode Implementation ---

StringCompareNode::StringCompareNode(std::string name, std::vector<ASTPtr> a, std::string o, std::string t)
    : funcName(std::move(name)), args(std::move(a)), op(std::move(o)), target(std::move(t)), m_bound_string_func(nullptr) {}

int StringCompareNode::eval() const {
    if (!m_bound_string_func) {
        // If unbound, default to false (safe failure)
        // Or throw if we want to be strict. Let's be safe.
        return 0;
    }

    // Evaluate integer arguments (e.g., index)
    std::vector<int> evalArgs;
    for(const auto& a : args) evalArgs.push_back(a->eval());

    // Get the zero-copy view from the lambda
    std::string_view actual = (*m_bound_string_func)(evalArgs);

    // Perform comparison
    if (op == "==") return actual == target;
    if (op == "!=") return actual != target;

    // Future: 'contains', 'startswith', etc.

    return 0;
}

std::unique_ptr<ASTNode> StringCompareNode::clone() const {
    std::vector<ASTPtr> c_args;
    for(const auto& a : args) c_args.push_back(a->clone());
    return std::make_unique<StringCompareNode>(funcName, std::move(c_args), op, target);
}

// --- Parser Updates ---

FnParser::FnParser(const std::string& input) : tokenizer(input) { advance(); }
void FnParser::advance() { current = tokenizer.next(); }

ASTPtr FnParser::parsePrimary() {
    if (current.type == TokenType::NUMBER) {
        int val = std::stoi(current.value);
        advance();
        return std::make_unique<ConstNode>(val);
    }
    if (current.type == TokenType::IDENT) {
        std::string name = current.value;
        advance();
        if (current.type == TokenType::LPAREN) {
            advance();
            std::vector<ASTPtr> args;
            if (current.type != TokenType::RPAREN) {
                do {
                    args.push_back(parseExpression());
                    if (current.type == TokenType::COMMA) advance();
                } while (current.type != TokenType::RPAREN);
            }
            advance();
            // We return a FuncCallNode initially. The PARENT (parseComparison)
            // will convert it to a StringCompareNode if it sees a string literal next.
            return std::make_unique<FuncCallNode>(name, std::move(args));
        }
        throw std::runtime_error("Expected function call");
    }
    if (current.type == TokenType::OP && current.value == "!") {
        std::string op = current.value;
        advance();
        return std::make_unique<UnaryNode>(op, parsePrimary());
    }
    if (current.type == TokenType::LPAREN) {
        advance();
        ASTPtr expr = parseExpression();
        if (current.type != TokenType::RPAREN) throw std::runtime_error("Expected ')'");
        advance();
        return expr;
    }
    throw std::runtime_error("Unexpected token: " + current.value);
}

ASTPtr FnParser::parseComparison() {
    ASTPtr left = parsePrimary();

    // Check if we have a comparison operator
    while (current.type == TokenType::OP &&
           (current.value == "==" || current.value == "!=" ||
            current.value == "<" || current.value == ">" ||
            current.value == "<=" || current.value == ">="))
    {
        std::string op = current.value;
        advance();

        // --- NEW: Check for String Literal on RHS ---
        if (current.type == TokenType::STRING) {
            std::string targetStr = current.value;
            advance();

            // We must convert 'left' (which is currently a FuncCallNode)
            // into a StringCompareNode.
            auto* funcNode = dynamic_cast<FuncCallNode*>(left.get());
            if (!funcNode) {
                throw std::runtime_error("String comparison requires a function on the left side.");
            }

            // Create the specialized string node
            // We steal the name and args from the FuncCallNode
            // Note: This assumes 'left' was just created and we own it.
            auto strNode = std::make_unique<StringCompareNode>(
                funcNode->name,
                std::move(funcNode->args), // stealing ownership of args
                op,
                targetStr
            );

            left = std::move(strNode);
        }
        else {
            // Standard integer comparison
            ASTPtr right = parsePrimary();
            left = std::make_unique<BinaryNode>(std::move(left), op, std::move(right));
        }
    }
    return left;
}

ASTPtr FnParser::parseAnd() {
    ASTPtr left = parseComparison();
    while (current.type == TokenType::OP && current.value == "AND") {
        std::string op = current.value;
        advance();
        ASTPtr right = parseComparison();
        left = std::make_unique<BinaryNode>(std::move(left), op, std::move(right));
    }
    return left;
}

ASTPtr FnParser::parseOr() {
    ASTPtr left = parseAnd();
    while (current.type == TokenType::OP && current.value == "OR") {
        std::string op = current.value;
        advance();
        ASTPtr right = parseAnd();
        left = std::make_unique<BinaryNode>(std::move(left), op, std::move(right));
    }
    return left;
}

ASTPtr FnParser::parseExpression() { return parseOr(); }
ASTPtr FnParser::parse() { return parseOr(); }

} // namespace pcapabvparser

