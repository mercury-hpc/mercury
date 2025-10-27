/*
 * Copyright (c) 2010, Oracle America, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 *     * Neither the name of the "Oracle America, Inc." nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 *   FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 *   COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 *   INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 *   GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *   WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * rpc_scan.h, Definitions for the RPCL scanner
 */

#ifndef RPC_SCAN_H
#define RPC_SCAN_H

/*
 * kinds of tokens
 */
enum tok_kind {
    TOK_IDENT,     /* malloced ident string */
    TOK_CHARCONST, /* malloced char const */
    TOK_STRCONST,  /* malloced string const */
    TOK_UNDEFINED,
    TOK_STRSTATIC, /* static string, not malloced */
    TOK_LPAREN,
    TOK_RPAREN,
    TOK_LBRACE,
    TOK_RBRACE,
    TOK_LBRACKET,
    TOK_RBRACKET,
    TOK_LANGLE,
    TOK_RANGLE,
    TOK_STAR,
    TOK_COMMA,
    TOK_EQUAL,
    TOK_COLON,
    TOK_SEMICOLON,
    TOK_CONST,
    TOK_STRUCT,
    TOK_UNION,
    TOK_SWITCH,
    TOK_CASE,
    TOK_DEFAULT,
    TOK_ENUM,
    TOK_TYPEDEF,
    TOK_INT,
    TOK_SHORT,
    TOK_LONG,
    TOK_HYPER,
    TOK_UNSIGNED,
    TOK_FLOAT,
    TOK_DOUBLE,
    TOK_QUAD,
    TOK_OPAQUE,
    TOK_CHAR,
    TOK_STRING,
    TOK_BOOL,
    TOK_VOID,
    TOK_PROGRAM,
    TOK_VERSION,
    TOK_EOF
};
typedef enum tok_kind tok_kind;

/*
 * a token
 */
struct token {
    tok_kind kind;
    char *str;
};
typedef struct token token;

/*
 * routine interface
 */
void
scan(tok_kind, token *);
void
scan2(tok_kind, tok_kind, token *);
void
scan3(tok_kind, tok_kind, tok_kind, token *);
void
scan_num(token *);
void
peek(token *);
int
peekscan(tok_kind, token *);
void
init_token(token *);
void
free_token_str(token *);
void
get_token(token *);
#endif /* RPC_SCAN_H */
