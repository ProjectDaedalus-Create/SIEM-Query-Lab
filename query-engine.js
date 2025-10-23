// SIEM Query Lab - Query Engine

class QueryEngine {
    constructor() {
        this.parsers = {
            'sql': this.parseSQL.bind(this),
            'spl': this.parseSPL.bind(this),
            'kql': this.parseKQL.bind(this),
            'sigma': this.parseSigma.bind(this)
        };
    }
    
    execute(query, data, language) {
        const parser = this.parsers[language];
        if (!parser) {
            throw new Error(`Unsupported query language: ${language}`);
        }
        
        return parser(query, data);
    }
    
    // SQL Parser
    parseSQL(query, data) {
        query = query.trim().replace(/;$/, '');
        const lowerQuery = query.toLowerCase();
        
        // Basic SELECT parser
        if (!lowerQuery.startsWith('select')) {
            throw new Error('Query must start with SELECT');
        }
        
        let results = [...data];
        
        // Parse WHERE clause
        const whereMatch = query.match(/WHERE\s+(.+?)(?:\s+ORDER\s+BY|\s+LIMIT|\s+GROUP\s+BY|$)/i);
        if (whereMatch) {
            const whereClause = whereMatch[1].trim();
            results = this.applyWhereClause(results, whereClause);
        }
        
        // Parse GROUP BY
        const groupByMatch = query.match(/GROUP\s+BY\s+([^\s,]+)(?:\s+ORDER\s+BY|\s+LIMIT|$)/i);
        if (groupByMatch) {
            const groupByField = groupByMatch[1].trim();
            results = this.applyGroupBy(results, groupByField, query);
        }
        
        // Parse ORDER BY
        const orderByMatch = query.match(/ORDER\s+BY\s+([^\s,]+)(?:\s+(ASC|DESC))?(?:\s+LIMIT|$)/i);
        if (orderByMatch) {
            const orderField = orderByMatch[1].trim();
            const direction = (orderByMatch[2] || 'ASC').toUpperCase();
            results = this.applyOrderBy(results, orderField, direction);
        }
        
        // Parse LIMIT
        const limitMatch = query.match(/LIMIT\s+(\d+)/i);
        if (limitMatch) {
            const limit = parseInt(limitMatch[1]);
            results = results.slice(0, limit);
        }
        
        // Parse SELECT fields
        const selectMatch = query.match(/SELECT\s+(.+?)\s+FROM/i);
        if (selectMatch) {
            const selectClause = selectMatch[1].trim();
            if (selectClause !== '*') {
                results = this.applySelectFields(results, selectClause);
            }
        }
        
        return results;
    }
    
    applyWhereClause(data, whereClause) {
        // Handle simple conditions
        return data.filter(row => {
            // Split by AND/OR (simplified)
            const conditions = whereClause.split(/\s+AND\s+/i);
            
            return conditions.every(condition => {
                // Match: field operator value
                const match = condition.match(/([a-zA-Z_][a-zA-Z0-9_]*)\s*(=|!=|>|<|>=|<=|LIKE)\s*['"]?([^'"]+)['"]?/i);
                if (!match) return true;
                
                const [, field, operator, value] = match;
                const fieldValue = row[field];
                
                if (fieldValue === undefined) return false;
                
                switch (operator.toUpperCase()) {
                    case '=':
                        return String(fieldValue).toLowerCase() === value.toLowerCase();
                    case '!=':
                        return String(fieldValue).toLowerCase() !== value.toLowerCase();
                    case '>':
                        return Number(fieldValue) > Number(value);
                    case '<':
                        return Number(fieldValue) < Number(value);
                    case '>=':
                        return Number(fieldValue) >= Number(value);
                    case '<=':
                        return Number(fieldValue) <= Number(value);
                    case 'LIKE':
                        const pattern = value.replace(/%/g, '.*');
                        return new RegExp(pattern, 'i').test(String(fieldValue));
                    default:
                        return false;
                }
            });
        });
    }
    
    applySelectFields(data, selectClause) {
        const fields = selectClause.split(',').map(f => {
            const trimmed = f.trim();
            // Handle COUNT, SUM, etc.
            const aggMatch = trimmed.match(/(COUNT|SUM|AVG|MAX|MIN)\(([^)]+)\)(?:\s+AS\s+([a-zA-Z_][a-zA-Z0-9_]*))?/i);
            if (aggMatch) {
                return { type: 'agg', func: aggMatch[1], field: aggMatch[2], alias: aggMatch[3] };
            }
            // Handle aliases
            const aliasMatch = trimmed.match(/([a-zA-Z_][a-zA-Z0-9_]*)\s+AS\s+([a-zA-Z_][a-zA-Z0-9_]*)/i);
            if (aliasMatch) {
                return { type: 'field', name: aliasMatch[1], alias: aliasMatch[2] };
            }
            return { type: 'field', name: trimmed };
        });
        
        return data.map(row => {
            const newRow = {};
            fields.forEach(field => {
                if (field.type === 'field') {
                    const key = field.alias || field.name;
                    newRow[key] = row[field.name];
                }
            });
            return newRow;
        });
    }
    
    applyGroupBy(data, groupByField, fullQuery) {
        const grouped = {};
        
        data.forEach(row => {
            const key = row[groupByField];
            if (!grouped[key]) {
                grouped[key] = [];
            }
            grouped[key].push(row);
        });
        
        // Parse aggregate functions
        const selectMatch = fullQuery.match(/SELECT\s+(.+?)\s+FROM/i);
        if (!selectMatch) return data;
        
        const selectClause = selectMatch[1];
        const aggMatches = [...selectClause.matchAll(/(COUNT|SUM|AVG)\(([^)]+)\)(?:\s+AS\s+([a-zA-Z_][a-zA-Z0-9_]*))?/gi)];
        
        return Object.entries(grouped).map(([key, rows]) => {
            const result = { [groupByField]: key };
            
            aggMatches.forEach(match => {
                const func = match[1].toUpperCase();
                const field = match[2].trim();
                const alias = match[3] || `${func.toLowerCase()}_${field}`;
                
                switch (func) {
                    case 'COUNT':
                        result[alias] = rows.length;
                        break;
                    case 'SUM':
                        result[alias] = rows.reduce((sum, r) => sum + (Number(r[field]) || 0), 0);
                        break;
                    case 'AVG':
                        result[alias] = rows.reduce((sum, r) => sum + (Number(r[field]) || 0), 0) / rows.length;
                        break;
                }
            });
            
            return result;
        });
    }
    
    applyOrderBy(data, field, direction) {
        return [...data].sort((a, b) => {
            const aVal = a[field];
            const bVal = b[field];
            
            if (aVal === bVal) return 0;
            
            const comparison = aVal < bVal ? -1 : 1;
            return direction === 'DESC' ? -comparison : comparison;
        });
    }
    
    // SPL Parser (Splunk Processing Language)
    parseSPL(query, data) {
        query = query.trim();
        let results = [...data];
        
        // Split by pipes
        const commands = query.split('|').map(cmd => cmd.trim()).filter(cmd => cmd);
        
        for (const command of commands) {
            if (command.startsWith('search ')) {
                results = this.applySPLSearch(results, command.substring(7));
            } else if (command.startsWith('where ')) {
                results = this.applySPLWhere(results, command.substring(6));
            } else if (command.startsWith('stats ')) {
                results = this.applySPLStats(results, command.substring(6));
            } else if (command.startsWith('table ')) {
                results = this.applySPLTable(results, command.substring(6));
            } else if (command.startsWith('head ')) {
                const limit = parseInt(command.substring(5));
                results = results.slice(0, limit);
            } else if (command.startsWith('tail ')) {
                const limit = parseInt(command.substring(5));
                results = results.slice(-limit);
            } else if (command.startsWith('sort ')) {
                results = this.applySPLSort(results, command.substring(5));
            }
        }
        
        return results;
    }
    
    applySPLSearch(data, searchClause) {
        return data.filter(row => {
            // Simple field=value search
            const conditions = searchClause.split(/\s+AND\s+/i);
            
            return conditions.every(condition => {
                const match = condition.match(/([a-zA-Z_][a-zA-Z0-9_]*)=["']?([^"'\s]+)["']?/);
                if (!match) return true;
                
                const [, field, value] = match;
                return String(row[field]).toLowerCase().includes(value.toLowerCase());
            });
        });
    }
    
    applySPLWhere(data, whereClause) {
        return this.applyWhereClause(data, whereClause);
    }
    
    applySPLStats(data, statsClause) {
        // Parse: count by field, avg(field) by groupfield, etc.
        const byMatch = statsClause.match(/\s+by\s+([a-zA-Z_][a-zA-Z0-9_]*)/i);
        const groupField = byMatch ? byMatch[1] : null;
        
        if (groupField) {
            const grouped = {};
            data.forEach(row => {
                const key = row[groupField];
                if (!grouped[key]) grouped[key] = [];
                grouped[key].push(row);
            });
            
            return Object.entries(grouped).map(([key, rows]) => {
                const result = { [groupField]: key };
                
                // Parse aggregations
                const countMatch = statsClause.match(/count(?:\(([^)]+)\))?/i);
                if (countMatch) {
                    result.count = rows.length;
                }
                
                return result;
            });
        }
        
        return data;
    }
    
    applySPLTable(data, tableClause) {
        const fields = tableClause.split(/\s+/).filter(f => f);
        return data.map(row => {
            const newRow = {};
            fields.forEach(field => {
                if (row.hasOwnProperty(field)) {
                    newRow[field] = row[field];
                }
            });
            return newRow;
        });
    }
    
    applySPLSort(data, sortClause) {
        const parts = sortClause.trim().split(/\s+/);
        const field = parts[0];
        const direction = parts[1] === '-' || sortClause.startsWith('-') ? 'DESC' : 'ASC';
        const cleanField = field.replace(/^-/, '');
        
        return this.applyOrderBy(data, cleanField, direction);
    }
    
    // KQL Parser (Kusto Query Language)
    parseKQL(query, data) {
        query = query.trim();
        let results = [...data];
        
        // Split by pipes
        const commands = query.split('|').map(cmd => cmd.trim()).filter(cmd => cmd);
        
        for (const command of commands) {
            if (command.startsWith('where ')) {
                results = this.applyKQLWhere(results, command.substring(6));
            } else if (command.startsWith('summarize ')) {
                results = this.applyKQLSummarize(results, command.substring(10));
            } else if (command.startsWith('project ')) {
                results = this.applyKQLProject(results, command.substring(8));
            } else if (command.startsWith('take ')) {
                const limit = parseInt(command.substring(5));
                results = results.slice(0, limit);
            } else if (command.startsWith('sort by ')) {
                results = this.applyKQLSort(results, command.substring(8));
            }
        }
        
        return results;
    }
    
    applyKQLWhere(data, whereClause) {
        return data.filter(row => {
            // Parse conditions with ==, contains, etc.
            const match = whereClause.match(/([a-zA-Z_][a-zA-Z0-9_]*)\s*(==|!=|>|<|contains)\s*["']?([^"']+)["']?/i);
            if (!match) return true;
            
            const [, field, operator, value] = match;
            const fieldValue = row[field];
            
            if (fieldValue === undefined) return false;
            
            switch (operator.toLowerCase()) {
                case '==':
                    return String(fieldValue).toLowerCase() === value.toLowerCase();
                case '!=':
                    return String(fieldValue).toLowerCase() !== value.toLowerCase();
                case 'contains':
                    return String(fieldValue).toLowerCase().includes(value.toLowerCase());
                case '>':
                    return Number(fieldValue) > Number(value);
                case '<':
                    return Number(fieldValue) < Number(value);
                default:
                    return false;
            }
        });
    }
    
    applyKQLSummarize(data, summarizeClause) {
        const byMatch = summarizeClause.match(/\s+by\s+([a-zA-Z_][a-zA-Z0-9_]*)/i);
        const groupField = byMatch ? byMatch[1] : null;
        
        if (groupField) {
            const grouped = {};
            data.forEach(row => {
                const key = row[groupField];
                if (!grouped[key]) grouped[key] = [];
                grouped[key].push(row);
            });
            
            return Object.entries(grouped).map(([key, rows]) => {
                const result = { [groupField]: key };
                
                const countMatch = summarizeClause.match(/count\(\)/i);
                if (countMatch) {
                    result.count = rows.length;
                }
                
                return result;
            });
        }
        
        return data;
    }
    
    applyKQLProject(data, projectClause) {
        const fields = projectClause.split(',').map(f => f.trim());
        return data.map(row => {
            const newRow = {};
            fields.forEach(field => {
                if (row.hasOwnProperty(field)) {
                    newRow[field] = row[field];
                }
            });
            return newRow;
        });
    }
    
    applyKQLSort(data, sortClause) {
        const parts = sortClause.split(/\s+/);
        const field = parts[0];
        const direction = parts[1] === 'desc' ? 'DESC' : 'ASC';
        
        return this.applyOrderBy(data, field, direction);
    }
    
    // Sigma Parser (Simplified - returns matching events)
    parseSigma(query, data) {
        // Very simplified Sigma parser - just checks for field matches
        const detectionMatch = query.match(/detection:\s*\n\s*selection:\s*\n([\s\S]+?)(?:\n\s*condition:|$)/);
        if (!detectionMatch) {
            throw new Error('Invalid Sigma rule format');
        }
        
        const selectionBlock = detectionMatch[1];
        const conditions = {};
        
        // Parse simple field: value pairs
        const matches = selectionBlock.matchAll(/\s+([a-zA-Z_][a-zA-Z0-9_]*):\s*['"]?([^'"\n]+)['"]?/g);
        for (const match of matches) {
            conditions[match[1]] = match[2].trim();
        }
        
        return data.filter(row => {
            return Object.entries(conditions).every(([field, value]) => {
                return String(row[field]).toLowerCase().includes(value.toLowerCase());
            });
        });
    }
}
