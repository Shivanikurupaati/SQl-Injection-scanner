"""
Feature extraction module for SQL injection detection.
Extracts various features from SQL queries to train ML models.
Enhanced for complex payload detection.
"""

import re
import numpy as np
from typing import List, Dict


class SQLFeatureExtractor:
    """Extracts features from SQL queries for injection detection."""
    
    # SQL injection patterns - expanded for complex payloads
    SQL_KEYWORDS = [
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER',
        'EXEC', 'EXECUTE', 'UNION', 'SCRIPT', 'TABLE', 'DATABASE', 'SCHEMA',
        'TRUNCATE', 'GRANT', 'REVOKE', 'SHUTDOWN', 'SHOW', 'DESCRIBE', 'DESC',
        'INFORMATION_SCHEMA', 'SYS', 'SYSTEM', 'DUAL', 'CONCAT', 'SUBSTRING',
        'MID', 'LENGTH', 'CHAR', 'ASCII', 'ORD', 'HEX', 'UNHEX', 'BENCHMARK',
        'SLEEP', 'WAITFOR', 'DELAY', 'IF', 'CASE', 'WHEN', 'THEN', 'ELSE',
        'HAVING', 'GROUP BY', 'ORDER BY', 'LIMIT', 'OFFSET', 'TOP', 'ROWNUM'
    ]
    
    SQL_INJECTION_PATTERNS = [
        r"('|(\\')|(;)|(--)|(/\*)|(\*/)|(\+)|(\%)|(\=)|(\()|(\))|(\[)|(\])|(\{)|(\}))",
        r"(OR|AND)\s+\d+\s*=\s*\d+",
        r"(OR|AND)\s+['\"]\w+['\"]\s*=\s*['\"]\w+['\"]",
        r"UNION\s+(ALL\s+)?SELECT",
        r"EXEC\s*\(",
        r"xp_\w+",
        r"sp_\w+",
        r"CAST\s*\(",
        r"CONVERT\s*\(",
        r"WAITFOR\s+DELAY",
        r"BENCHMARK\s*\(",
        r"LOAD_FILE\s*\(",
        r"INTO\s+OUTFILE",
        r"INTO\s+DUMPFILE",
        r"SLEEP\s*\(",
        r"PG_SLEEP\s*\(",
        r"IF\s*\([^)]+\)\s*SLEEP",
        r"'\s*(OR|AND)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
        r"'\s*(OR|AND)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+",
        r"UNION\s+SELECT\s+NULL",
        r"ORDER\s+BY\s+\d+",
        r"GROUP\s+BY\s+\d+",
        r"HAVING\s+\d+\s*=\s*\d+",
        r"INFORMATION_SCHEMA",
        r"sys\.\w+",
        r"@@\w+",
        r"CONCAT\s*\(",
        r"CHAR\s*\(",
        r"ASCII\s*\(",
        r"SUBSTRING\s*\(",
        r"MID\s*\(",
        r"HEX\s*\(",
        r"UNHEX\s*\(",
        r"0x[0-9a-fA-F]+",
        r"%[0-9a-fA-F]{2}",
        r"CHR\s*\(",
        r"STRCMP\s*\(",
        r"LIKE\s+['\"]%",
        r"RLIKE\s+",
        r"REGEXP\s+",
        r"EXTRACTVALUE\s*\(",
        r"UPDATEXML\s*\(",
        r"LOAD_DATA\s+INFILE",
        r"INTO\s+DUMPFILE",
    ]
    
    def __init__(self):
        self.patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.SQL_INJECTION_PATTERNS]
    
    def extract_features(self, query: str) -> np.ndarray:
        """
        Extract features from a SQL query.
        Enhanced for complex payload detection.
        
        Args:
            query: SQL query string
            
        Returns:
            numpy array of features
        """
        features = []
        query_lower = query.lower()
        query_upper = query.upper()
        
        # 1. Length features
        features.append(len(query))
        features.append(len(query.split()))
        features.append(len(query.split(';')))
        
        # 2. Character frequency features
        features.append(query.count("'"))
        features.append(query.count('"'))
        features.append(query.count(';'))
        features.append(query.count('--'))
        features.append(query.count('/*'))
        features.append(query.count('*/'))
        features.append(query.count('='))
        features.append(query.count('('))
        features.append(query.count(')'))
        features.append(query.count('['))
        features.append(query.count(']'))
        features.append(query.count('{'))
        features.append(query.count('}'))
        features.append(query.count('+'))
        features.append(query.count('%'))
        features.append(query.count('*'))
        features.append(query.count('|'))
        features.append(query.count('&'))
        features.append(query.count('^'))
        
        # 3. SQL keyword counts
        for keyword in self.SQL_KEYWORDS:
            features.append(query_upper.count(keyword))
        
        # 4. SQL injection pattern matches
        pattern_matches = 0
        for pattern in self.patterns:
            if pattern.search(query):
                pattern_matches += 1
        features.append(pattern_matches)
        
        # 5. Ratio features
        if len(query) > 0:
            features.append(query.count("'") / len(query))
            features.append(query.count('=') / len(query))
            features.append(query.count('(') / len(query))
        else:
            features.extend([0, 0, 0])
        
        # 6. Special character sequences
        features.append(1 if '--' in query else 0)
        features.append(1 if '/*' in query else 0)
        features.append(1 if '*/' in query else 0)
        features.append(1 if ';' in query else 0)
        features.append(1 if 'OR 1=1' in query_upper or 'OR\'1\'=\'1\'' in query_upper else 0)
        features.append(1 if 'UNION' in query_upper else 0)
        features.append(1 if 'EXEC' in query_upper else 0)
        features.append(1 if 'DROP' in query_upper else 0)
        features.append(1 if 'DELETE' in query_upper else 0)
        features.append(1 if 'INSERT' in query_upper else 0)
        features.append(1 if 'UPDATE' in query_upper else 0)
        
        # 7. Encoding/obfuscation features
        features.append(1 if '%' in query else 0)
        features.append(1 if '0x' in query_lower else 0)
        features.append(1 if 'CHAR(' in query_upper else 0)
        features.append(1 if 'ASCII(' in query_upper else 0)
        
        # 8. Comment patterns
        features.append(query.count('--'))
        features.append(query.count('/*'))
        features.append(query.count('*/'))
        
        # 9. Boolean logic patterns
        features.append(1 if re.search(r'\d+\s*=\s*\d+', query) else 0)
        features.append(1 if re.search(r"'\w+'\s*=\s*'\w+'", query) else 0)
        
        # 10. Function calls
        features.append(len(re.findall(r'\w+\s*\(', query)))
        
        # 11. Time-based injection patterns (complex payloads)
        features.append(1 if re.search(r'SLEEP\s*\(', query_upper) else 0)
        features.append(1 if re.search(r'WAITFOR\s+DELAY', query_upper) else 0)
        features.append(1 if re.search(r'BENCHMARK\s*\(', query_upper) else 0)
        features.append(1 if re.search(r'PG_SLEEP\s*\(', query_upper) else 0)
        
        # 12. Blind SQL injection patterns
        features.append(1 if re.search(r'IF\s*\([^)]+\)\s*\w+', query_upper) else 0)
        features.append(1 if re.search(r'CASE\s+WHEN', query_upper) else 0)
        features.append(1 if re.search(r'IIF\s*\(', query_upper) else 0)
        
        # 13. Stacked queries (multiple statements)
        features.append(len(re.findall(r';\s*\w+', query)))
        features.append(1 if ';' in query and len(query.split(';')) > 2 else 0)
        
        # 14. Information schema access
        features.append(1 if 'INFORMATION_SCHEMA' in query_upper else 0)
        features.append(1 if re.search(r'sys\.\w+', query_lower) else 0)
        features.append(1 if re.search(r'@@\w+', query) else 0)
        
        # 15. Encoding and obfuscation (complex)
        features.append(len(re.findall(r'%[0-9a-fA-F]{2}', query)))
        features.append(len(re.findall(r'0x[0-9a-fA-F]+', query_lower)))
        features.append(1 if re.search(r'CHAR\s*\([^)]+\)', query_upper) else 0)
        features.append(1 if re.search(r'CONCAT\s*\(', query_upper) else 0)
        features.append(1 if re.search(r'HEX\s*\(', query_upper) else 0)
        features.append(1 if re.search(r'UNHEX\s*\(', query_upper) else 0)
        features.append(1 if re.search(r'FROM_BASE64\s*\(', query_upper) else 0)
        features.append(1 if re.search(r'TO_BASE64\s*\(', query_upper) else 0)
        
        # 16. XML-based injection
        features.append(1 if 'EXTRACTVALUE' in query_upper else 0)
        features.append(1 if 'UPDATEXML' in query_upper else 0)
        features.append(1 if '<' in query and '>' in query else 0)
        
        # 17. Second-order injection patterns
        features.append(1 if re.search(r"'\s*;\s*\w+", query) else 0)
        features.append(1 if re.search(r"'\s*UNION\s+", query_upper) else 0)
        
        # 18. NoSQL injection patterns (if applicable)
        features.append(1 if '$where' in query_lower else 0)
        features.append(1 if '$ne' in query_lower else 0)
        features.append(1 if '$gt' in query_lower else 0)
        features.append(1 if '$lt' in query_lower else 0)
        features.append(1 if '$regex' in query_lower else 0)
        
        # 19. Advanced boolean-based patterns
        features.append(1 if re.search(r"'\s*(OR|AND)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", query_upper) else 0)
        features.append(1 if re.search(r"'\s*(OR|AND)\s+['\"]?\w+['\"]?\s*LIKE\s+", query_upper) else 0)
        
        # 20. Error-based injection
        features.append(1 if re.search(r'EXTRACTVALUE\s*\(', query_upper) else 0)
        features.append(1 if re.search(r'UPDATEXML\s*\(', query_upper) else 0)
        features.append(1 if re.search(r'FLOOR\s*\([^)]*RAND\s*\(', query_upper) else 0)
        
        # 21. Out-of-band injection
        features.append(1 if 'LOAD_FILE' in query_upper else 0)
        features.append(1 if 'INTO OUTFILE' in query_upper else 0)
        features.append(1 if 'INTO DUMPFILE' in query_upper else 0)
        
        # 22. Nested queries depth
        nested_depth = 0
        paren_count = 0
        max_depth = 0
        for char in query:
            if char == '(':
                paren_count += 1
                max_depth = max(max_depth, paren_count)
            elif char == ')':
                paren_count -= 1
        features.append(max_depth)
        
        # 23. Query complexity metrics
        features.append(len(re.findall(r'\s+AND\s+', query_upper)))
        features.append(len(re.findall(r'\s+OR\s+', query_upper)))
        features.append(len(re.findall(r'\s+UNION\s+', query_upper)))
        
        # 24. String manipulation functions
        features.append(1 if 'SUBSTRING' in query_upper or 'SUBSTR' in query_upper else 0)
        features.append(1 if 'MID' in query_upper else 0)
        features.append(1 if 'LEFT' in query_upper else 0)
        features.append(1 if 'RIGHT' in query_upper else 0)
        features.append(1 if 'REPLACE' in query_upper else 0)
        
        return np.array(features, dtype=np.float32)
    
    def get_feature_names(self) -> List[str]:
        """Get list of feature names for interpretability."""
        names = []
        
        names.extend(['query_length', 'word_count', 'semicolon_count'])
        names.extend(['single_quote_count', 'double_quote_count', 'semicolon_char_count',
                     'double_dash_count', 'comment_start_count', 'comment_end_count',
                     'equals_count', 'open_paren_count', 'close_paren_count',
                     'open_bracket_count', 'close_bracket_count', 'open_brace_count',
                     'close_brace_count', 'plus_count', 'percent_count', 'asterisk_count',
                     'pipe_count', 'ampersand_count', 'caret_count'])
        names.extend([f'keyword_{kw.lower().replace(" ", "_")}' for kw in self.SQL_KEYWORDS])
        names.append('pattern_match_count')
        names.extend(['single_quote_ratio', 'equals_ratio', 'paren_ratio'])
        names.extend(['has_double_dash', 'has_comment_start', 'has_comment_end',
                     'has_semicolon', 'has_or_1_equals_1', 'has_union', 'has_exec',
                     'has_drop', 'has_delete', 'has_insert', 'has_update'])
        names.extend(['has_percent', 'has_hex', 'has_char_func', 'has_ascii_func'])
        names.extend(['double_dash_freq', 'comment_start_freq', 'comment_end_freq'])
        names.extend(['has_boolean_equals', 'has_string_equals', 'function_call_count'])
        names.extend(['has_sleep', 'has_waitfor', 'has_benchmark', 'has_pg_sleep'])
        names.extend(['has_if_statement', 'has_case_when', 'has_iif'])
        names.extend(['semicolon_statements', 'has_multiple_statements'])
        names.extend(['has_information_schema', 'has_sys_table', 'has_system_var'])
        names.extend(['url_encoded_count', 'hex_encoded_count', 'has_char_func_call',
                     'has_concat', 'has_hex_func', 'has_unhex', 'has_from_base64', 'has_to_base64'])
        names.extend(['has_extractvalue', 'has_updatexml', 'has_xml_tags'])
        names.extend(['has_second_order_semicolon', 'has_second_order_union'])
        names.extend(['has_nosql_where', 'has_nosql_ne', 'has_nosql_gt', 'has_nosql_lt', 'has_nosql_regex'])
        names.extend(['has_advanced_boolean', 'has_like_injection'])
        names.extend(['has_extractvalue_error', 'has_updatexml_error', 'has_floor_rand'])
        names.extend(['has_load_file', 'has_into_outfile', 'has_into_dumpfile'])
        names.extend(['max_nested_depth'])
        names.extend(['and_count', 'or_count', 'union_count'])
        names.extend(['has_substring', 'has_mid', 'has_left', 'has_right', 'has_replace'])
        
        return names

