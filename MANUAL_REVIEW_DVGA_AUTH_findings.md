# Manual Review: PF-GRAPHQL-AUTH-001 Findings in DVGA

**Date:** 2026-07-03  
**Reviewer:** Automated review with manual code inspection  
**Rule:** PF-GRAPHQL-AUTH-001 (GraphQL IDOR: object by id without ownership)  
**Repo:** DVGA (Damn Vulnerable GraphQL App)

## Methodology

Each of the 6 `PF-GRAPHQL-AUTH-001` findings was manually reviewed by
inspecting the code at the reported line and checking for:
1. Is the object fetched by a user-supplied `id`?
2. Is there any ownership check (current_user, owner_id, user_id)?
3. Is there any authorization check (auth decorator, permission check)?
4. Is this actually exploitable as IDOR?

## Findings

### 1. core/views.py:141 — EditPaste.mutate

```python
def mutate(self, info, id, title=None, content=None):
    paste_obj = Paste.query.filter_by(id=id).first()
```

**Verdict: TRUE POSITIVE (IDOR)**  
The `EditPaste` mutation accepts a user-supplied `id` and fetches a paste
by that id with `filter_by(id=id)`. There is no ownership check — any
authenticated user can edit any paste by guessing/enumerating the id. The
`info` parameter is passed but only used for `Audit.create_audit_entry(info)`,
not for authorization.

---

### 2. core/views.py:148 — EditPaste.mutate (update)

```python
Paste.query.filter_by(id=id).update(dict(title=title, content=content))
```

**Verdict: TRUE POSITIVE (IDOR)**  
Same mutation as #1, but this is the `update` call. The paste is updated
by user-supplied `id` without ownership verification. This is the second
IDOR in the same mutation — the fetch (line 141) and the update (line 148).

**Note:** This is arguably a duplicate of finding #1 since it's the same
mutation. The rule fires on every `filter_by(id=id)` line, which is correct
behavior — both lines are independently vulnerable. Deduplication of
same-function findings is a B10 task.

---

### 3. core/views.py:167 — DeletePaste.mutate

```python
def mutate(self, info, id):
    result = False
    if Paste.query.filter_by(id=id).delete():
```

**Verdict: TRUE POSITIVE (IDOR)**  
The `DeletePaste` mutation accepts a user-supplied `id` and deletes a paste
by that id. No ownership check. Any user can delete any paste by id. This
is a critical IDOR — deletion is irreversible.

---

### 4. core/views.py:330 — resolve_paste

```python
def resolve_paste(self, info, id=None, title=None):
    query = PasteObject.get_query(info)
    Audit.create_audit_entry(info)
    if title:
        return query.filter_by(title=title, burn=False).first()
    return query.filter_by(id=id, burn=False).first()
```

**Verdict: TRUE POSITIVE (IDOR)**  
The `resolve_paste` query resolver fetches a paste by user-supplied `id`.
No ownership check. Any user can read any paste (including "burned" ones
that should have been destroyed — note `burn=False` only filters out
already-burned pastes, but the id is user-controlled).

---

### 5. core/views.py:358 — resolve_read_and_burn

```python
def resolve_read_and_burn(self, info, id):
    result = Paste.query.filter_by(id=id, burn=True).first()
    Paste.query.filter_by(id=id, burn=True).delete()
```

**Verdict: TRUE POSITIVE (IDOR)**  
The `resolve_read_and_burn` resolver reads and then deletes a "burned"
paste by user-supplied `id`. No ownership check. Any user can read and
burn any paste by id. This is both an IDOR and a data destruction issue.

---

### 6. core/views.py:374 — resolve_users

```python
def resolve_users(self, info, id=None):
    query = UserObject.get_query(info)
    Audit.create_audit_entry(info)
    if id:
        result = query.filter_by(id=id)
```

**Verdict: TRUE POSITIVE (IDOR)**  
The `resolve_users` resolver fetches user records by user-supplied `id`.
No ownership or authorization check. Any user can query any other user's
data by id. This is a user enumeration / IDOR vulnerability.

## Summary

| # | Location | Function | Verdict | Severity |
|---|----------|----------|---------|----------|
| 1 | views.py:141 | EditPaste.mutate | TRUE POSITIVE | High (IDOR write) |
| 2 | views.py:148 | EditPaste.mutate | TRUE POSITIVE (dup of #1) | High |
| 3 | views.py:167 | DeletePaste.mutate | TRUE POSITIVE | Critical (IDOR delete) |
| 4 | views.py:330 | resolve_paste | TRUE POSITIVE | Medium (IDOR read) |
| 5 | views.py:358 | resolve_read_and_burn | TRUE POSITIVE | High (IDOR read + delete) |
| 6 | views.py:374 | resolve_users | TRUE POSITIVE | High (user enumeration) |

**All 6 findings are TRUE POSITIVES.** Zero false positives.

## Observations

1. **DVGA is intentionally vulnerable** — it's the "Damn Vulnerable GraphQL
   App." All IDOR findings are expected by design.

2. **Finding #2 is a same-function duplicate of #1.** Both are in
   `EditPaste.mutate` — line 141 (fetch) and line 148 (update). The rule
   fires on each `filter_by(id=id)` line independently, which is correct
   but produces a duplicate finding. This is a B10 dedup target.

3. **No false positives.** The rule correctly identified all 6 IDOR
   patterns without flagging any safe code. The safe pattern suppression
   (checking for `current_user`, `owner`, `auth`, etc.) correctly did not
   suppress these because DVGA has no ownership checks.

4. **Rule confidence is correctly set to "low."** The rule is heuristic
   and cannot prove the absence of ownership checks across function
   boundaries. In this case, the heuristic is correct, but in other
   codebases it may produce false positives. The `inform` default mode
   is appropriate.

## Recommendation

The 6 `PF-GRAPHQL-AUTH-001` findings in DVGA are all true positives. The
rule is performing correctly. The findings should remain as `inform` by
default (not `block`) because:

1. The rule is heuristic and may produce false positives in codebases with
   cross-function ownership checks.
2. DVGA is a deliberately vulnerable app — real apps may have auth
   middleware that the rule cannot detect.
3. The rule's `confidence: low` and `maturity: beta` correctly reflect
   its heuristic nature.

The rule should only be promoted to `block` after broader testing on
real-world codebases with diverse auth patterns.
