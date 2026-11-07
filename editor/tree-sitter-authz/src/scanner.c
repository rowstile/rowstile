// What a regular expression can't read in a condition's SQL, read as core/authzlib/parse.py's Scanner does (and
// Postgres): a dollar quote, whose closing tag is its opening one ($tag$...$tag$), and a /* comment */, which nests.
// Each is one token, so a brace or a quote inside opens or closes nothing. Written by hand, unlike the rest of src/.
#include "tree_sitter/parser.h"

#include <stdbool.h>
#include <stdint.h>

enum TokenType { DOLLAR_QUOTE, BLOCK_COMMENT, ERROR_SENTINEL };

// a tag longer than this isn't read as one (Postgres names are at most 63 bytes)
#define TAG_MAX 64

void *tree_sitter_authz_external_scanner_create(void) { return NULL; }

void tree_sitter_authz_external_scanner_destroy(void *payload) { (void)payload; }

unsigned tree_sitter_authz_external_scanner_serialize(void *payload, char *buffer) {
  (void)payload;
  (void)buffer;
  return 0;
}

void tree_sitter_authz_external_scanner_deserialize(void *payload, const char *buffer, unsigned length) {
  (void)payload;
  (void)buffer;
  (void)length;
}

// a letter of a tag, as of an unquoted name: ASCII letters, _, any character past ASCII, and digits after the first
static bool tag_char(int32_t c, bool first) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' || c >= 0x80 || (!first && c >= '0' && c <= '9');
}

static void advance(TSLexer *lexer) { lexer->advance(lexer, false); }

// $$...$$ or $tag$...$tag$, from the $ that opens it (a $ right after a name's letter is the name's: the grammar's
// token for a name reads it, and this one is never asked there)
static bool dollar_quote(TSLexer *lexer) {
  int32_t tag[TAG_MAX];
  unsigned n = 0;
  advance(lexer);
  while (lexer->lookahead != '$') {
    if (n == TAG_MAX || !tag_char(lexer->lookahead, n == 0)) return false;
    tag[n++] = lexer->lookahead;
    advance(lexer);
  }
  advance(lexer);
  while (!lexer->eof(lexer)) {
    if (lexer->lookahead != '$') {
      advance(lexer);
      continue;
    }
    advance(lexer);
    unsigned i = 0;
    while (i < n && lexer->lookahead == tag[i]) {
      advance(lexer);
      i++;
    }
    if (i == n && lexer->lookahead == '$') {
      advance(lexer);
      lexer->result_symbol = DOLLAR_QUOTE;
      return true;
    }
    // (not the tag: the character here, a $ too perhaps, is read again)
  }
  return false;
}

// /* ... */, from the / that opens it: each /* inside opens one more, each */ closes one
static bool block_comment(TSLexer *lexer) {
  advance(lexer);
  if (lexer->lookahead != '*') return false;
  advance(lexer);
  unsigned depth = 1;
  while (depth && !lexer->eof(lexer)) {
    int32_t c = lexer->lookahead;
    advance(lexer);
    if (c == '*' && lexer->lookahead == '/') {
      advance(lexer);
      depth--;
    } else if (c == '/' && lexer->lookahead == '*') {
      advance(lexer);
      depth++;
    }
  }
  if (depth) return false;
  lexer->result_symbol = BLOCK_COMMENT;
  return true;
}

bool tree_sitter_authz_external_scanner_scan(void *payload, TSLexer *lexer, const bool *valid_symbols) {
  (void)payload;
  // (while the parser recovers from an error, every token is asked for: the grammar's own tokens then)
  if (valid_symbols[ERROR_SENTINEL]) return false;
  while (lexer->lookahead == ' ' || lexer->lookahead == '\t' || lexer->lookahead == '\n' || lexer->lookahead == '\r' ||
         lexer->lookahead == '\f' || lexer->lookahead == '\v') {
    lexer->advance(lexer, true);
  }
  if (lexer->lookahead == '$' && valid_symbols[DOLLAR_QUOTE]) return dollar_quote(lexer);
  if (lexer->lookahead == '/' && valid_symbols[BLOCK_COMMENT]) return block_comment(lexer);
  return false;
}
