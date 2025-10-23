// SIEM Query Lab - Challenge & Course Content

const CHALLENGES = {
    sql: [
        {
            type: 'theory',
            title: '1. Introduction to SQL for Security',
            description: 'Understanding SQL basics and how it applies to security data analysis.',
            theory: [
                'SQL (Structured Query Language) is a standard language for managing and querying relational databases.',
                'In security contexts, SQL is used to query SIEM databases, log repositories, and security data warehouses.',
                'Basic SQL structure: SELECT columns FROM table WHERE conditions',
                'Key components: SELECT (what to retrieve), FROM (where to retrieve from), WHERE (filtering conditions)',
                'Common security use cases: searching authentication logs, analyzing failed logins, tracking user activity'
            ]
        },
        {
            type: 'guided',
            title: '2. Basic SELECT Queries',
            description: 'Learn to retrieve data using SELECT statements',
            theory: [
                'The SELECT statement retrieves data from a database.',
                'Use * to select all columns, or specify column names separated by commas.',
                'The FROM clause specifies which table to query.',
                'Always end SQL statements with a semicolon.'
            ],
            examples: [
                {
                    description: 'Select all authentication events',
                    query: 'SELECT * FROM auth_logs;'
                },
                {
                    description: 'Select specific columns',
                    query: 'SELECT username, action, timestamp FROM auth_logs;'
                }
            ],
            task: 'Retrieve only the username and source_ip columns from the authentication logs.',
            dataSource: 'auth_logs',
            starterQuery: 'SELECT ',
            hint: 'List the column names separated by commas after SELECT',
            validation: (results) => {
                return results.length > 0 && 
                       results[0].hasOwnProperty('username') && 
                       results[0].hasOwnProperty('source_ip') &&
                       Object.keys(results[0]).length === 2;
            }
        },
        {
            type: 'guided',
            title: '3. Filtering with WHERE',
            description: 'Filter data using WHERE conditions',
            theory: [
                'The WHERE clause filters rows based on conditions.',
                'Common operators: = (equals), != (not equals), > (greater than), < (less than)',
                'Use AND to combine multiple conditions, OR for alternatives.',
                'String values must be enclosed in single quotes.'
            ],
            examples: [
                {
                    description: 'Find failed login attempts',
                    query: "SELECT * FROM auth_logs WHERE action = 'failed_login';"
                },
                {
                    description: 'Find specific user activity',
                    query: "SELECT * FROM auth_logs WHERE username = 'admin';"
                }
            ],
            task: 'Find all authentication events where the action was "failed_login".',
            dataSource: 'auth_logs',
            starterQuery: 'SELECT * FROM auth_logs WHERE ',
            hint: 'Use the = operator with the action column',
            validation: (results) => {
                return results.length > 0 && results.every(r => r.action === 'failed_login');
            }
        },
        {
            type: 'practical',
            title: '4. Sorting with ORDER BY',
            description: 'Sort query results in ascending or descending order',
            theory: [
                'ORDER BY sorts results based on one or more columns.',
                'Use ASC for ascending order (default), DESC for descending order.',
                'Useful for finding the most recent events or highest values.'
            ],
            examples: [
                {
                    description: 'Sort by timestamp, newest first',
                    query: "SELECT * FROM auth_logs WHERE action = 'failed_login' ORDER BY timestamp DESC;"
                }
            ],
            task: 'Retrieve all failed logins sorted by timestamp with the newest events first.',
            dataSource: 'auth_logs',
            hint: 'Combine WHERE with ORDER BY timestamp DESC',
            validation: (results) => {
                if (results.length < 2) return false;
                return results.every(r => r.action === 'failed_login');
            }
        },
        {
            type: 'practical',
            title: '5. Limiting Results',
            description: 'Control the number of results returned',
            theory: [
                'LIMIT restricts the number of rows returned.',
                'Useful for performance and focusing on top results.',
                'Often combined with ORDER BY to get "top N" results.'
            ],
            examples: [
                {
                    description: 'Get the 5 most recent events',
                    query: 'SELECT * FROM auth_logs ORDER BY timestamp DESC LIMIT 5;'
                }
            ],
            task: 'Find the 3 most recent failed login attempts.',
            dataSource: 'auth_logs',
            hint: 'Filter for failed_login, order by timestamp DESC, and limit to 3',
            validation: (results) => {
                return results.length === 3 && results.every(r => r.action === 'failed_login');
            }
        },
        {
            type: 'practical',
            title: '6. Aggregation with COUNT',
            description: 'Count rows and group data',
            theory: [
                'COUNT() returns the number of rows.',
                'GROUP BY groups rows that have the same values.',
                'Aggregation functions: COUNT, SUM, AVG, MAX, MIN',
                'Use GROUP BY with aggregate functions to analyze patterns.'
            ],
            examples: [
                {
                    description: 'Count login attempts per user',
                    query: 'SELECT username, COUNT(*) AS attempt_count FROM auth_logs GROUP BY username;'
                }
            ],
            task: 'Count how many events occurred for each action type.',
            dataSource: 'auth_logs',
            hint: 'SELECT action, COUNT(*) ... GROUP BY action',
            validation: (results) => {
                return results.length > 0 && results.every(r => 
                    r.hasOwnProperty('action') && r.hasOwnProperty('count')
                );
            }
        },
        {
            type: 'challenge',
            title: '7. Investigation Challenge',
            description: 'Real-world security investigation scenario',
            task: 'Security Alert: Multiple failed login attempts detected. Your mission: Identify which username has the most failed login attempts. Return the username and the count of failed attempts, ordered by count (highest first).',
            dataSource: 'auth_logs',
            hint: 'Filter WHERE action = failed_login, GROUP BY username, COUNT, ORDER BY DESC',
            validation: (results) => {
                return results.length > 0 && 
                       results[0].hasOwnProperty('username') &&
                       results.every(r => typeof r.count === 'number');
            }
        }
    ],
    
    spl: [
        {
            type: 'theory',
            title: '1. Introduction to SPL',
            description: 'Understanding Splunk Processing Language fundamentals',
            theory: [
                'SPL (Splunk Processing Language) is the query language used in Splunk.',
                'SPL uses a pipeline approach: commands are chained together with the pipe (|) character.',
                'Data flows left to right through each command in the pipeline.',
                'Basic structure: search criteria | transform | format',
                'SPL is case-insensitive for commands but case-sensitive for field values.'
            ]
        },
        {
            type: 'guided',
            title: '2. Search Command Basics',
            description: 'Learn the fundamental search command',
            theory: [
                'The search command filters events based on keywords and field values.',
                'Syntax: search field=value',
                'Multiple criteria can be combined with AND/OR.',
                'Wildcards (*) can be used for partial matches.'
            ],
            examples: [
                {
                    description: 'Search for failed logins',
                    query: 'search action=failed_login'
                },
                {
                    description: 'Search for specific user',
                    query: 'search username=admin'
                }
            ],
            task: 'Search for all events where the action is "successful_login".',
            dataSource: 'auth_logs',
            starterQuery: 'search ',
            hint: 'Use action=successful_login',
            validation: (results) => {
                return results.length > 0 && results.every(r => r.action === 'successful_login');
            }
        },
        {
            type: 'guided',
            title: '3. Table Command',
            description: 'Format output with specific fields',
            theory: [
                'The table command displays only specified fields.',
                'Syntax: | table field1 field2 field3',
                'Useful for cleaning up output and focusing on relevant data.',
                'Fields are displayed in the order specified.'
            ],
            examples: [
                {
                    description: 'Display specific fields',
                    query: 'search action=failed_login | table username source_ip timestamp'
                }
            ],
            task: 'Search for failed logins and display only the username and source_ip fields.',
            dataSource: 'auth_logs',
            starterQuery: 'search action=failed_login | table ',
            hint: 'List the field names after table command',
            validation: (results) => {
                return results.length > 0 && 
                       results[0].hasOwnProperty('username') && 
                       results[0].hasOwnProperty('source_ip');
            }
        },
        {
            type: 'practical',
            title: '4. Stats Command',
            description: 'Aggregate and analyze data',
            theory: [
                'The stats command performs statistical operations.',
                'Common functions: count, sum, avg, max, min',
                'Use "by" clause to group results.',
                'Syntax: | stats count by field'
            ],
            examples: [
                {
                    description: 'Count events by user',
                    query: 'search action=failed_login | stats count by username'
                }
            ],
            task: 'Count how many failed login attempts each username has.',
            dataSource: 'auth_logs',
            hint: 'search action=failed_login | stats count by username',
            validation: (results) => {
                return results.length > 0 && 
                       results.every(r => r.hasOwnProperty('username') && r.hasOwnProperty('count'));
            }
        },
        {
            type: 'practical',
            title: '5. Sort Command',
            description: 'Order results for better analysis',
            theory: [
                'The sort command orders results by specified fields.',
                'Prefix with - for descending order, or use + for ascending.',
                'Default is ascending order.',
                'Can sort by multiple fields.'
            ],
            examples: [
                {
                    description: 'Sort by count descending',
                    query: 'search * | stats count by action | sort -count'
                }
            ],
            task: 'Find failed logins per user and sort by count (highest first).',
            dataSource: 'auth_logs',
            hint: 'Use stats count by username, then sort -count',
            validation: (results) => {
                return results.length > 0 && results.every(r => r.hasOwnProperty('count'));
            }
        },
        {
            type: 'practical',
            title: '6. Head Command',
            description: 'Limit results to top N events',
            theory: [
                'The head command returns the first N results.',
                'Syntax: | head N',
                'Often used after sorting to get top results.',
                'Useful for performance and focusing analysis.'
            ],
            examples: [
                {
                    description: 'Get top 5 users by failed logins',
                    query: 'search action=failed_login | stats count by username | sort -count | head 5'
                }
            ],
            task: 'Find the top 3 usernames with the most failed login attempts.',
            dataSource: 'auth_logs',
            hint: 'Combine stats, sort, and head commands',
            validation: (results) => {
                return results.length <= 3 && results.every(r => r.hasOwnProperty('username'));
            }
        },
        {
            type: 'challenge',
            title: '7. Threat Hunting Challenge',
            description: 'Identify suspicious authentication patterns',
            task: 'Security Alert: Potential brute force attack detected. Find the top user with failed login attempts, show their username and count, and identify the source IPs they used. Use multiple pipeline commands.',
            dataSource: 'auth_logs',
            hint: 'Start with search action=failed_login, use stats to count by username, sort, head, then search again for that user',
            validation: (results) => {
                return results.length > 0;
            }
        }
    ],
    
    kql: [
        {
            type: 'theory',
            title: '1. Introduction to KQL',
            description: 'Understanding Kusto Query Language for Microsoft security tools',
            theory: [
                'KQL (Kusto Query Language) is used in Azure Sentinel, Microsoft Defender, and Azure Data Explorer.',
                'KQL uses a tabular data model with pipe-based syntax.',
                'Queries flow from table name through pipe operators.',
                'KQL is case-sensitive for string comparisons but not for operators.',
                'Common in cloud security and Microsoft ecosystem security operations.'
            ]
        },
        {
            type: 'guided',
            title: '2. Where Operator',
            description: 'Filter data with where conditions',
            theory: [
                'The where operator filters rows based on predicates.',
                'Use == for equality (not single =).',
                'Common operators: ==, !=, >, <, contains, startswith, endswith',
                'String comparisons are case-sensitive by default.'
            ],
            examples: [
                {
                    description: 'Filter by action',
                    query: 'auth_logs | where action == "failed_login"'
                },
                {
                    description: 'Filter with contains',
                    query: 'auth_logs | where username contains "admin"'
                }
            ],
            task: 'Filter authentication logs to show only successful logins.',
            dataSource: 'auth_logs',
            starterQuery: 'auth_logs | where ',
            hint: 'Use action == "successful_login"',
            validation: (results) => {
                return results.length > 0 && results.every(r => r.action === 'successful_login');
            }
        },
        {
            type: 'guided',
            title: '3. Project Operator',
            description: 'Select specific columns',
            theory: [
                'The project operator selects which columns to include in results.',
                'Similar to SELECT in SQL.',
                'Can rename columns and create calculated columns.',
                'Helps reduce data size and focus on relevant fields.'
            ],
            examples: [
                {
                    description: 'Select specific columns',
                    query: 'auth_logs | where action == "failed_login" | project username, source_ip, timestamp'
                }
            ],
            task: 'Show failed logins with only username and source_ip columns.',
            dataSource: 'auth_logs',
            starterQuery: 'auth_logs | where action == "failed_login" | project ',
            hint: 'List the column names: username, source_ip',
            validation: (results) => {
                return results.length > 0 && 
                       results[0].hasOwnProperty('username') && 
                       results[0].hasOwnProperty('source_ip');
            }
        },
        {
            type: 'practical',
            title: '4. Summarize Operator',
            description: 'Aggregate and group data',
            theory: [
                'The summarize operator performs aggregations.',
                'Common functions: count(), sum(), avg(), max(), min()',
                'Use "by" to group results.',
                'Essential for statistical analysis and pattern detection.'
            ],
            examples: [
                {
                    description: 'Count by action type',
                    query: 'auth_logs | summarize count() by action'
                }
            ],
            task: 'Count failed login attempts for each username.',
            dataSource: 'auth_logs',
            hint: 'Filter where action == "failed_login", then summarize count() by username',
            validation: (results) => {
                return results.length > 0 && 
                       results.every(r => r.hasOwnProperty('username') && r.hasOwnProperty('count'));
            }
        },
        {
            type: 'practical',
            title: '5. Sort and Take Operators',
            description: 'Order and limit results',
            theory: [
                'The sort operator orders results by one or more columns.',
                'Use "desc" for descending, "asc" for ascending (default).',
                'The take operator limits results to N rows.',
                'Combine for "top N" queries.'
            ],
            examples: [
                {
                    description: 'Top 5 users by activity',
                    query: 'auth_logs | summarize count() by username | sort by count desc | take 5'
                }
            ],
            task: 'Find the top 3 users with the most failed login attempts.',
            dataSource: 'auth_logs',
            hint: 'Filter, summarize count() by username, sort by count desc, take 3',
            validation: (results) => {
                return results.length <= 3 && results.every(r => r.hasOwnProperty('username'));
            }
        },
        {
            type: 'practical',
            title: '6. Extend Operator',
            description: 'Create calculated columns',
            theory: [
                'The extend operator adds calculated columns.',
                'Can perform string operations, math, datetime calculations.',
                'New columns can be used in subsequent operators.',
                'Useful for enriching data during analysis.'
            ],
            examples: [
                {
                    description: 'Add a calculated field',
                    query: 'auth_logs | extend hour = timestamp | project username, hour, action'
                }
            ],
            task: 'Project username and action fields from all authentication logs.',
            dataSource: 'auth_logs',
            hint: 'auth_logs | project username, action',
            validation: (results) => {
                return results.length > 0;
            }
        },
        {
            type: 'challenge',
            title: '7. Advanced Threat Detection',
            description: 'Multi-stage security investigation',
            task: 'Incident Response: Investigate authentication anomalies. Find users with more than 2 failed login attempts, sorted by attempt count (highest first). Show username and count.',
            dataSource: 'auth_logs',
            hint: 'where action == "failed_login" | summarize count() by username | where count > 2 | sort by count desc',
            validation: (results) => {
                return results.length >= 0 && results.every(r => r.hasOwnProperty('count'));
            }
        }
    ],
    
    sigma: [
        {
            type: 'theory',
            title: '1. Introduction to Sigma',
            description: 'Understanding Sigma detection rules',
            theory: [
                'Sigma is a generic signature format for SIEM systems.',
                'Allows writing detection rules once and converting to any SIEM query language.',
                'Uses YAML format for rule definition.',
                'Key components: title, description, detection (selection + condition), level',
                'Designed for sharing threat detection rules across platforms.'
            ]
        },
        {
            type: 'guided',
            title: '2. Basic Sigma Rule Structure',
            description: 'Learn Sigma rule components',
            theory: [
                'Title: Brief description of what the rule detects',
                'Description: Detailed explanation of the threat',
                'Detection: Contains selection criteria and conditions',
                'Selection: Field-value pairs that must match',
                'Condition: Logic for how selections combine',
                'Level: Severity (low, medium, high, critical)'
            ],
            examples: [
                {
                    description: 'Detect failed logins',
                    query: `title: Failed Login Attempts
description: Detects failed authentication attempts
detection:
  selection:
    action: 'failed_login'
  condition: selection
level: medium`
                }
            ],
            task: 'Create a Sigma rule that detects successful login events. Use the template provided.',
            dataSource: 'auth_logs',
            starterQuery: `title: Successful Logins
description: Detects successful authentication
detection:
  selection:
    action: 'successful_login'
  condition: selection
level: low`,
            hint: 'Change action value to successful_login',
            validation: (results) => {
                return results.length > 0;
            }
        },
        {
            type: 'guided',
            title: '3. Multiple Field Selection',
            description: 'Match on multiple criteria',
            theory: [
                'Selections can include multiple field-value pairs.',
                'All fields in a selection must match (AND logic).',
                'Useful for precise threat detection.',
                'Can filter on any available log fields.'
            ],
            examples: [
                {
                    description: 'Detect admin failed logins',
                    query: `title: Admin Failed Login
description: Failed login to admin account
detection:
  selection:
    username: 'admin'
    action: 'failed_login'
  condition: selection
level: high`
                }
            ],
            task: 'Detect failed login attempts from a specific user (choose any username from the data).',
            dataSource: 'auth_logs',
            hint: 'Add both username and action fields to selection',
            validation: (results) => {
                return results.length >= 0;
            }
        },
        {
            type: 'practical',
            title: '4. Detection Patterns',
            description: 'Build practical threat detection rules',
            theory: [
                'Sigma rules should focus on specific attack patterns.',
                'Use appropriate severity levels based on threat impact.',
                'Consider false positive rate when designing rules.',
                'Document your detection logic clearly.'
            ],
            task: 'Create a rule to detect any authentication failures. Set level to medium.',
            dataSource: 'auth_logs',
            starterQuery: `title: Authentication Failures
description: 
detection:
  selection:
    action: 
  condition: selection
level: `,
            hint: 'Fill in the action field with failed_login and set level to medium',
            validation: (results) => {
                return true;
            }
        },
        {
            type: 'challenge',
            title: '5. Advanced Detection Rule',
            description: 'Create a comprehensive detection rule',
            task: 'Create a Sigma rule to detect potential brute force attacks: multiple failed login attempts. Make it as specific as possible with appropriate severity.',
            dataSource: 'auth_logs',
            hint: 'Focus on failed_login action, consider high severity level',
            validation: (results) => {
                return true;
            }
        }
    ]
};

// Export for use in main.js
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CHALLENGES;
}
