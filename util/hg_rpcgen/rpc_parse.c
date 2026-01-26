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
 * rpc_parse.c, Parser for the RPC protocol compiler
 * Copyright (C) 1987 Sun Microsystems, Inc.
 */
#include "rpc_parse.h"
#include "rpc_scan.h"
#include "rpc_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARGNAME "arg"

static void
isdefined(definition *);
static void
def_struct(definition *);
static void
def_program(definition *);
static void
def_enum(definition *);
static void
def_const(definition *);
static void
def_union(definition *);
static void
check_type_name(const char *, int);
static void
def_typedef(definition *);
static void
get_declaration(declaration *, defkind);
static void
get_prog_declaration(declaration *, defkind, int);
static void
get_type(token *, token *, defkind);
static void
unsigned_dec(token *);

static void
free_declaration(declaration *d)
{
    free_token_str(&d->prefix);
    free_token_str(&d->type);
    free_token_str(&d->name);
    free_token_str(&d->array_max);
}

static void
free_proc_list(proc_list *procs)
{
    proc_list *pl, *plnxt;
    decl_list *dl, *dlnxt;
    for (pl = procs; pl; pl = plnxt) {
        plnxt = pl->next;
        free_token_str(&pl->proc_name);
        free_token_str(&pl->proc_num);
        free_token_str(&pl->args.argname);
        for (dl = pl->args.decls; dl; dl = dlnxt) {
            dlnxt = dl->next;
            free_declaration(&dl->decl);
            free(dl);
        }
        free_token_str(&pl->res_type);
        free_token_str(&pl->res_prefix);
        free(pl);
    }
}

/*
 * free list of definitions
 */
void
free_definitions(list **dlistp)
{
    list *dl = *dlistp;
    list *nxt;
    definition *d;
    decl_list *dcl, *dclnxt;
    case_list *cl, *clnxt;
    enumval_list *el, *elnxt;
    version_list *vl, *vlnxt;

    *dlistp = NULL;

    for (; dl != NULL; dl = nxt) {
        d = dl->val;
        nxt = dl->next;
        free(dl);

        switch (d->def_kind) {
            case DEF_CONST:
                free_token_str(&d->def.co);
                break;
            case DEF_STRUCT:
                for (dcl = d->def.st.decls; dcl; dcl = dclnxt) {
                    dclnxt = dcl->next;
                    free_declaration(&dcl->decl);
                    free(dcl);
                }
                break;
            case DEF_UNION:
                free_declaration(&d->def.un.enum_decl);
                for (cl = d->def.un.cases; cl; cl = clnxt) {
                    clnxt = cl->next;
                    free_token_str(&cl->case_name);
                    free_declaration(&cl->case_decl);
                    free(cl);
                }
                if (d->def.un.default_decl) {
                    free_declaration(d->def.un.default_decl);
                    free(d->def.un.default_decl);
                }
                break;
            case DEF_ENUM:
                for (el = d->def.en.vals; el != NULL; el = elnxt) {
                    elnxt = el->next;
                    free_token_str(&el->name);
                    free_token_str(&el->assignment);
                    free(el);
                }
                break;
            case DEF_TYPEDEF:
                free_token_str(&d->def.ty.old_prefix);
                free_token_str(&d->def.ty.old_type);
                free_token_str(&d->def.ty.array_max);
                break;
            case DEF_PROGRAM:
                free_token_str(&d->def.pr.prog_num);
                for (vl = d->def.pr.versions; vl; vl = vlnxt) {
                    vlnxt = vl->next;
                    free_token_str(&vl->vers_name);
                    free_token_str(&vl->vers_num);
                    free_proc_list(vl->procs);
                    free(vl);
                }
                break;
            default:
                break;
        }
        free_token_str(&d->def_name);
        free(d);
    }
}

/*
 * return the next definition you see
 */
definition *
get_definition(void)
{
    definition *defp;
    token tok;

    defp = ALLOC(definition);
    get_token(&tok);
    switch (tok.kind) {
        case TOK_STRUCT:
            def_struct(defp);
            break;
        case TOK_UNION:
            def_union(defp);
            break;
        case TOK_TYPEDEF:
            def_typedef(defp);
            break;
        case TOK_ENUM:
            def_enum(defp);
            break;
        case TOK_PROGRAM:
            def_program(defp);
            break;
        case TOK_CONST:
            def_const(defp);
            break;
        case TOK_EOF:
            free(defp);
            return (NULL);
        default:
            error("Expected definition keyword");
    }
    scan(TOK_SEMICOLON, &tok);
    isdefined(defp);
    return (defp);
}

static void
isdefined(definition *defp)
{
    STOREVAL(&defined, defp);
}

static void
def_struct(definition *defp)
{
    token tok;
    declaration dec;
    decl_list *decls;
    decl_list **tailp;

    defp->def_kind = DEF_STRUCT;

    scan(TOK_IDENT, &defp->def_name);
    scan(TOK_LBRACE, &tok);
    tailp = &defp->def.st.decls;
    do {
        get_declaration(&dec, DEF_STRUCT);
        decls = ALLOC(decl_list);
        decls->decl = dec;
        *tailp = decls;
        tailp = &decls->next;
        scan(TOK_SEMICOLON, &tok);
        peek(&tok);
    } while (tok.kind != TOK_RBRACE);
    get_token(&tok);
    *tailp = NULL;
}

static void
def_program(definition *defp)
{
    token tok;
    declaration dec;
    decl_list *decls;
    decl_list **tailp;
    version_list *vlist;
    version_list **vtailp;
    proc_list *plist;
    proc_list **ptailp;
    int num_args;
    int isvoid = 0; /* whether first argument is void */
    defp->def_kind = DEF_PROGRAM;
    scan(TOK_IDENT, &defp->def_name);
    scan(TOK_LBRACE, &tok);
    vtailp = &defp->def.pr.versions;
    tailp = &defp->def.st.decls;
    scan(TOK_VERSION, &tok);
    do {
        vlist = ALLOC(version_list);
        scan(TOK_IDENT, &vlist->vers_name);
        scan(TOK_LBRACE, &tok);
        ptailp = &vlist->procs;
        do {
            /* get result type */
            plist = ALLOC(proc_list);
            get_type(&plist->res_prefix, &plist->res_type, DEF_PROGRAM);
            if (streq(plist->res_type.str, "opaque")) {
                error("Illegal result type");
            }
            scan(TOK_IDENT, &plist->proc_name);
            scan(TOK_LPAREN, &tok);
            /* get args - first one */
            num_args = 1;
            isvoid = 0;
            /* type of DEF_PROGRAM in the first
             * get_prog_declaration and DEF_STRUCT in the next
             * allows void as argument if it is the only argument */
            get_prog_declaration(&dec, DEF_PROGRAM, num_args);
            if (streq(dec.type.str, "void"))
                isvoid = 1;
            decls = ALLOC(decl_list);
            plist->args.decls = decls;
            decls->decl = dec;
            tailp = &decls->next;
            /* get args */
            while (peekscan(TOK_COMMA, &tok)) {
                num_args++;
                get_prog_declaration(&dec, DEF_STRUCT, num_args);
                decls = ALLOC(decl_list);
                decls->decl = dec;
                *tailp = decls;
                if (streq(dec.type.str, "void"))
                    isvoid = 1;
                tailp = &decls->next;
            }
            /* multiple arguments are only allowed in new style */
            if (num_args > 1) {
                error("Only one argument is allowed");
            }
            if (isvoid && num_args > 1) {
                error("Illegal use of void in program definition");
            }
            *tailp = NULL;
            scan(TOK_RPAREN, &tok);
            scan(TOK_EQUAL, &tok);
            scan_num(&plist->proc_num);
            scan(TOK_SEMICOLON, &tok);
            plist->arg_num = num_args;
            *ptailp = plist;
            ptailp = &plist->next;
            peek(&tok);
        } while (tok.kind != TOK_RBRACE);
        *ptailp = NULL;
        *vtailp = vlist;
        vtailp = &vlist->next;
        scan(TOK_RBRACE, &tok);
        scan(TOK_EQUAL, &tok);
        scan_num(&vlist->vers_num);
        /* make the argument structure name for each arg */
        for (plist = vlist->procs; plist != NULL; plist = plist->next) {
            plist->args.argname.kind = TOK_IDENT;
            plist->args.argname.str =
                make_argname(plist->proc_name.str, vlist->vers_num.str);
        }
        scan(TOK_SEMICOLON, &tok);
        scan2(TOK_VERSION, TOK_RBRACE, &tok);
    } while (tok.kind == TOK_VERSION);
    scan(TOK_EQUAL, &tok);
    scan_num(&defp->def.pr.prog_num);
    *vtailp = NULL;
}

static void
def_enum(definition *defp)
{
    token tok;
    enumval_list *elist;
    enumval_list **tailp;

    defp->def_kind = DEF_ENUM;
    scan(TOK_IDENT, &defp->def_name);
    scan(TOK_LBRACE, &tok);
    tailp = &defp->def.en.vals;
    do {
        scan(TOK_IDENT, &tok);
        elist = ALLOC(enumval_list);
        elist->name = tok;
        init_token(&elist->assignment);
        scan3(TOK_COMMA, TOK_RBRACE, TOK_EQUAL, &tok);
        if (tok.kind == TOK_EQUAL) {
            scan_num(&elist->assignment);
            scan2(TOK_COMMA, TOK_RBRACE, &tok);
        }
        *tailp = elist;
        tailp = &elist->next;
    } while (tok.kind != TOK_RBRACE);
    *tailp = NULL;
}

static void
def_const(definition *defp)
{
    token tok;

    defp->def_kind = DEF_CONST;
    scan(TOK_IDENT, &defp->def_name);
    scan(TOK_EQUAL, &tok);
    scan2(TOK_IDENT, TOK_STRCONST, &defp->def.co);
}

static void
def_union(definition *defp)
{
    token tok;
    declaration dec;
    case_list *cases;
    case_list **tailp;

    defp->def_kind = DEF_UNION;
    scan(TOK_IDENT, &defp->def_name);
    scan(TOK_SWITCH, &tok);
    scan(TOK_LPAREN, &tok);
    get_declaration(&dec, DEF_UNION);
    defp->def.un.enum_decl = dec;
    tailp = &defp->def.un.cases;
    scan(TOK_RPAREN, &tok);
    scan(TOK_LBRACE, &tok);
    scan(TOK_CASE, &tok);
    while (tok.kind == TOK_CASE) {
        scan2(TOK_IDENT, TOK_CHARCONST, &tok);
        cases = ALLOC(case_list);
        cases->case_name = tok;
        scan(TOK_COLON, &tok);
        /* now peek at next token */
        if (peekscan(TOK_CASE, &tok)) {

            do {
                scan2(TOK_IDENT, TOK_CHARCONST, &tok);
                cases->contflag = 1; /* continued case
                                      * statement */
                *tailp = cases;
                tailp = &cases->next;
                cases = ALLOC(case_list);
                cases->case_name = tok;
                scan(TOK_COLON, &tok);

            } while (peekscan(TOK_CASE, &tok));
        }
        get_declaration(&dec, DEF_UNION);
        cases->case_decl = dec;
        cases->contflag = 0; /* no continued case statement */
        *tailp = cases;
        tailp = &cases->next;
        scan(TOK_SEMICOLON, &tok);

        scan3(TOK_CASE, TOK_DEFAULT, TOK_RBRACE, &tok);
    }
    *tailp = NULL;
    if (tok.kind == TOK_DEFAULT) {
        scan(TOK_COLON, &tok);
        get_declaration(&dec, DEF_UNION);
        defp->def.un.default_decl = ALLOC(declaration);
        *defp->def.un.default_decl = dec;
        scan(TOK_SEMICOLON, &tok);
        scan(TOK_RBRACE, &tok);
    } else {
        defp->def.un.default_decl = NULL;
    }
}

static const char *const reserved_words[] = {"array", "bytes", "destroy",
    "free", "getpos", "inline", "pointer", "reference", "setpos", "sizeof",
    "union", "vector", NULL};

static const char *const reserved_types[] = {"opaque", "string", NULL};
/* check that the given name is not one that would eventually result in
   xdr routines that would conflict with internal XDR routines. */
static void
check_type_name(const char *name, int new_type)
{
    int i;

    for (i = 0; reserved_words[i] != NULL; i++) {
        if (strcmp(name, reserved_words[i]) == 0) {
            error("Illegal (reserved) name '%s' in type definition", name);
        }
    }
    if (new_type) {
        for (i = 0; reserved_types[i] != NULL; i++) {
            if (strcmp(name, reserved_types[i]) == 0) {
                error("Illegal (reserved) name '%s' in type definition", name);
            }
        }
    }
}

static void
def_typedef(definition *defp)
{
    declaration dec;

    defp->def_kind = DEF_TYPEDEF;
    get_declaration(&dec, DEF_TYPEDEF);
    defp->def_name = dec.name;
    check_type_name(dec.name.str, 1);
    defp->def.ty.old_prefix = dec.prefix;
    defp->def.ty.old_type = dec.type;
    defp->def.ty.rel = dec.rel;
    defp->def.ty.array_max = dec.array_max;
}

static void
get_declaration(declaration *dec, defkind dkind)
{
    token tok;

    /* make sure we fully init dec first */
    get_type(&dec->prefix, &dec->type, dkind);
    init_token(&dec->name);
    dec->rel = REL_ALIAS;
    init_token(&dec->array_max);

    if (streq(dec->type.str, "void")) {
        return;
    }
    check_type_name(dec->type.str, 0);

    scan2(TOK_STAR, TOK_IDENT, &tok);
    if (tok.kind == TOK_STAR) {
        dec->rel = REL_POINTER;
        scan(TOK_IDENT, &tok);
    }
    dec->name = tok;
    if (peekscan(TOK_LBRACKET, &tok)) {
        if (dec->rel == REL_POINTER) {
            error("No array-of-pointer declarations -- use typedef");
        }
        dec->rel = REL_VECTOR;
        scan_num(&dec->array_max);
        scan(TOK_RBRACKET, &tok);
    } else if (peekscan(TOK_LANGLE, &tok)) {
        if (dec->rel == REL_POINTER) {
            error("No array-of-pointer declarations -- use typedef");
        }
        dec->rel = REL_ARRAY;
        if (peekscan(TOK_RANGLE, &tok)) {
            dec->array_max.kind = TOK_STRSTATIC;
            dec->array_max.str = "(unsigned int)~0";
            /* unspecified size, use * max */
        } else {
            scan_num(&dec->array_max);
            scan(TOK_RANGLE, &tok);
        }
    }
    if (streq(dec->type.str, "opaque")) {
        if (dec->rel != REL_ARRAY && dec->rel != REL_VECTOR) {
            error("Array declaration expected");
        }
    } else if (streq(dec->type.str, "string")) {
        if (dec->rel != REL_ARRAY) {
            error("Variable-length array declaration expected");
        }
    }
}

static void
get_prog_declaration(declaration *dec, defkind dkind, int num /* arg number */)
{
    token tok;
    char name[255]; /* argument name */

    if (dkind == DEF_PROGRAM) {
        peek(&tok);
        if (tok.kind == TOK_RPAREN) { /* no arguments */
            dec->rel = REL_ALIAS;
            dec->type.kind = TOK_VOID;
            dec->type.str = "void";
            init_token(&dec->prefix);
            init_token(&dec->name);
            return;
        }
    }
    get_type(&dec->prefix, &dec->type, dkind);
    dec->rel = REL_ALIAS;
    if (!peekscan(TOK_IDENT, &dec->name)) { /* ok to use dec->name here */
        /* peekscan failed, must generate new dec->name */
        sprintf(name, "%s%d", ARGNAME, num); /* default name of
                                              * argument */
        dec->name.kind = TOK_IDENT;
        dec->name.str = strdup(name);
        if (!dec->name.str)
            error("strdup failed\n");
    }

    if (streq(dec->type.str, "void")) {
        return;
    }
    if (streq(dec->type.str, "opaque")) {
        error("Opaque -- illegal argument type");
    }
    if (peekscan(TOK_STAR, &tok)) {
        if (streq(dec->type.str, "string")) {
            error("Pointer to string not allowed in program arguments\n");
        }
        dec->rel = REL_POINTER;
        if (peekscan(TOK_IDENT, &tok)) {
            dec->name = tok; /* opt name of argument */
        }
    }
    if (peekscan(TOK_LANGLE, &tok)) {
        if (!streq(dec->type.str, "string")) {
            error("Arrays cannot be declared as arguments to procedures -- use "
                  "typedef");
        }
        dec->rel = REL_ARRAY;
        if (peekscan(TOK_RANGLE, &tok)) {
            dec->array_max.kind = TOK_STRSTATIC;
            dec->array_max.str = "(unsigned int)~0";
            /* unspecified size, use max */
        } else {
            scan_num(&dec->array_max);
            scan(TOK_RANGLE, &tok);
        }
    }
    if (streq(dec->type.str, "string")) {
        if (dec->rel != REL_ARRAY) { /* .x specifies just string as
                                      * type of argument - make it
                                      * string<> */
            dec->rel = REL_ARRAY;
            dec->array_max.kind = TOK_STRSTATIC;
            dec->array_max.str = "(unsigned int)~0";
            /* unspecified size, use max */
        }
    }
}

static void
get_type(token *prefixp, token *typep, defkind dkind)
{
    token tok;

    init_token(prefixp);
    get_token(&tok);
    switch (tok.kind) {
        case TOK_IDENT:
            *typep = tok;
            break;
        case TOK_STRUCT:
        case TOK_ENUM:
        case TOK_UNION:
            *prefixp = tok;
            scan(TOK_IDENT, typep);
            break;
        case TOK_UNSIGNED:
            unsigned_dec(typep);
            break;
        case TOK_SHORT:
            *typep = tok;
            (void) peekscan(TOK_INT, &tok);
            break;
        case TOK_LONG:
            *typep = tok;
            (void) peekscan(TOK_INT, &tok);
            break;
        case TOK_HYPER:
            *typep = tok;
            (void) peekscan(TOK_INT, &tok);
            break;
        case TOK_VOID:
            if (dkind != DEF_UNION && dkind != DEF_PROGRAM) {
                error("Void is allowed only inside union and program "
                      "definitions with one argument");
            }
            *typep = tok;
            break;
        case TOK_STRING:
        case TOK_OPAQUE:
        case TOK_CHAR:
        case TOK_INT:
        case TOK_FLOAT:
        case TOK_DOUBLE:
        case TOK_BOOL:
        case TOK_QUAD:
            *typep = tok;
            break;
        default:
            error("Type specifier expected");
    }
}

static void
unsigned_dec(token *typep)
{
    token tok;

    peek(&tok);
    switch (tok.kind) {
        case TOK_CHAR:
            get_token(&tok);
            *typep = tok;
            typep->str = "u_char";
            break;
        case TOK_SHORT:
            get_token(&tok);
            *typep = tok;
            typep->str = "u_short";
            (void) peekscan(TOK_INT, &tok);
            break;
        case TOK_LONG:
            get_token(&tok);
            *typep = tok;
            typep->str = "u_long";
            (void) peekscan(TOK_INT, &tok);
            break;
        case TOK_HYPER:
            get_token(&tok);
            *typep = tok;
            typep->str = "u_longlong_t";
            (void) peekscan(TOK_INT, &tok);
            break;
        case TOK_INT:
            get_token(&tok);
            *typep = tok;
            typep->str = "u_int";
            break;
        default:
            typep->kind = TOK_INT;
            typep->str = "u_int";
            break;
    }
}
