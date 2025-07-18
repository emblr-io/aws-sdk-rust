// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetPartitionsInput {
    /// <p>The ID of the Data Catalog where the partitions in question reside. If none is provided, the Amazon Web Services account ID is used by default.</p>
    pub catalog_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the catalog database where the partitions reside.</p>
    pub database_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the partitions' table.</p>
    pub table_name: ::std::option::Option<::std::string::String>,
    /// <p>An expression that filters the partitions to be returned.</p>
    /// <p>The expression uses SQL syntax similar to the SQL <code>WHERE</code> filter clause. The SQL statement parser <a href="http://jsqlparser.sourceforge.net/home.php">JSQLParser</a> parses the expression.</p>
    /// <p><i>Operators</i>: The following are the operators that you can use in the <code>Expression</code> API call:</p>
    /// <dl>
    /// <dt>
    /// =
    /// </dt>
    /// <dd>
    /// <p>Checks whether the values of the two operands are equal; if yes, then the condition becomes true.</p>
    /// <p>Example: Assume 'variable a' holds 10 and 'variable b' holds 20.</p>
    /// <p>(a = b) is not true.</p>
    /// </dd>
    /// <dt>
    /// &lt; &gt;
    /// </dt>
    /// <dd>
    /// <p>Checks whether the values of two operands are equal; if the values are not equal, then the condition becomes true.</p>
    /// <p>Example: (a &lt; &gt; b) is true.</p>
    /// </dd>
    /// <dt>
    /// &gt;
    /// </dt>
    /// <dd>
    /// <p>Checks whether the value of the left operand is greater than the value of the right operand; if yes, then the condition becomes true.</p>
    /// <p>Example: (a &gt; b) is not true.</p>
    /// </dd>
    /// <dt>
    /// &lt;
    /// </dt>
    /// <dd>
    /// <p>Checks whether the value of the left operand is less than the value of the right operand; if yes, then the condition becomes true.</p>
    /// <p>Example: (a &lt; b) is true.</p>
    /// </dd>
    /// <dt>
    /// &gt;=
    /// </dt>
    /// <dd>
    /// <p>Checks whether the value of the left operand is greater than or equal to the value of the right operand; if yes, then the condition becomes true.</p>
    /// <p>Example: (a &gt;= b) is not true.</p>
    /// </dd>
    /// <dt>
    /// &lt;=
    /// </dt>
    /// <dd>
    /// <p>Checks whether the value of the left operand is less than or equal to the value of the right operand; if yes, then the condition becomes true.</p>
    /// <p>Example: (a &lt;= b) is true.</p>
    /// </dd>
    /// <dt>
    /// AND, OR, IN, BETWEEN, LIKE, NOT, IS NULL
    /// </dt>
    /// <dd>
    /// <p>Logical operators.</p>
    /// </dd>
    /// </dl>
    /// <p><i>Supported Partition Key Types</i>: The following are the supported partition keys.</p>
    /// <ul>
    /// <li>
    /// <p><code>string</code></p></li>
    /// <li>
    /// <p><code>date</code></p></li>
    /// <li>
    /// <p><code>timestamp</code></p></li>
    /// <li>
    /// <p><code>int</code></p></li>
    /// <li>
    /// <p><code>bigint</code></p></li>
    /// <li>
    /// <p><code>long</code></p></li>
    /// <li>
    /// <p><code>tinyint</code></p></li>
    /// <li>
    /// <p><code>smallint</code></p></li>
    /// <li>
    /// <p><code>decimal</code></p></li>
    /// </ul>
    /// <p>If an type is encountered that is not valid, an exception is thrown.</p>
    /// <p>The following list shows the valid operators on each type. When you define a crawler, the <code>partitionKey</code> type is created as a <code>STRING</code>, to be compatible with the catalog partitions.</p>
    /// <p><i>Sample API Call</i>:</p>
    pub expression: ::std::option::Option<::std::string::String>,
    /// <p>A continuation token, if this is not the first call to retrieve these partitions.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The segment of the table's partitions to scan in this request.</p>
    pub segment: ::std::option::Option<crate::types::Segment>,
    /// <p>The maximum number of partitions to return in a single response.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>When true, specifies not returning the partition column schema. Useful when you are interested only in other partition attributes such as partition values or location. This approach avoids the problem of a large response by not returning duplicate data.</p>
    pub exclude_column_schema: ::std::option::Option<bool>,
    /// <p>The transaction ID at which to read the partition contents.</p>
    pub transaction_id: ::std::option::Option<::std::string::String>,
    /// <p>The time as of when to read the partition contents. If not set, the most recent transaction commit time will be used. Cannot be specified along with <code>TransactionId</code>.</p>
    pub query_as_of_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl GetPartitionsInput {
    /// <p>The ID of the Data Catalog where the partitions in question reside. If none is provided, the Amazon Web Services account ID is used by default.</p>
    pub fn catalog_id(&self) -> ::std::option::Option<&str> {
        self.catalog_id.as_deref()
    }
    /// <p>The name of the catalog database where the partitions reside.</p>
    pub fn database_name(&self) -> ::std::option::Option<&str> {
        self.database_name.as_deref()
    }
    /// <p>The name of the partitions' table.</p>
    pub fn table_name(&self) -> ::std::option::Option<&str> {
        self.table_name.as_deref()
    }
    /// <p>An expression that filters the partitions to be returned.</p>
    /// <p>The expression uses SQL syntax similar to the SQL <code>WHERE</code> filter clause. The SQL statement parser <a href="http://jsqlparser.sourceforge.net/home.php">JSQLParser</a> parses the expression.</p>
    /// <p><i>Operators</i>: The following are the operators that you can use in the <code>Expression</code> API call:</p>
    /// <dl>
    /// <dt>
    /// =
    /// </dt>
    /// <dd>
    /// <p>Checks whether the values of the two operands are equal; if yes, then the condition becomes true.</p>
    /// <p>Example: Assume 'variable a' holds 10 and 'variable b' holds 20.</p>
    /// <p>(a = b) is not true.</p>
    /// </dd>
    /// <dt>
    /// &lt; &gt;
    /// </dt>
    /// <dd>
    /// <p>Checks whether the values of two operands are equal; if the values are not equal, then the condition becomes true.</p>
    /// <p>Example: (a &lt; &gt; b) is true.</p>
    /// </dd>
    /// <dt>
    /// &gt;
    /// </dt>
    /// <dd>
    /// <p>Checks whether the value of the left operand is greater than the value of the right operand; if yes, then the condition becomes true.</p>
    /// <p>Example: (a &gt; b) is not true.</p>
    /// </dd>
    /// <dt>
    /// &lt;
    /// </dt>
    /// <dd>
    /// <p>Checks whether the value of the left operand is less than the value of the right operand; if yes, then the condition becomes true.</p>
    /// <p>Example: (a &lt; b) is true.</p>
    /// </dd>
    /// <dt>
    /// &gt;=
    /// </dt>
    /// <dd>
    /// <p>Checks whether the value of the left operand is greater than or equal to the value of the right operand; if yes, then the condition becomes true.</p>
    /// <p>Example: (a &gt;= b) is not true.</p>
    /// </dd>
    /// <dt>
    /// &lt;=
    /// </dt>
    /// <dd>
    /// <p>Checks whether the value of the left operand is less than or equal to the value of the right operand; if yes, then the condition becomes true.</p>
    /// <p>Example: (a &lt;= b) is true.</p>
    /// </dd>
    /// <dt>
    /// AND, OR, IN, BETWEEN, LIKE, NOT, IS NULL
    /// </dt>
    /// <dd>
    /// <p>Logical operators.</p>
    /// </dd>
    /// </dl>
    /// <p><i>Supported Partition Key Types</i>: The following are the supported partition keys.</p>
    /// <ul>
    /// <li>
    /// <p><code>string</code></p></li>
    /// <li>
    /// <p><code>date</code></p></li>
    /// <li>
    /// <p><code>timestamp</code></p></li>
    /// <li>
    /// <p><code>int</code></p></li>
    /// <li>
    /// <p><code>bigint</code></p></li>
    /// <li>
    /// <p><code>long</code></p></li>
    /// <li>
    /// <p><code>tinyint</code></p></li>
    /// <li>
    /// <p><code>smallint</code></p></li>
    /// <li>
    /// <p><code>decimal</code></p></li>
    /// </ul>
    /// <p>If an type is encountered that is not valid, an exception is thrown.</p>
    /// <p>The following list shows the valid operators on each type. When you define a crawler, the <code>partitionKey</code> type is created as a <code>STRING</code>, to be compatible with the catalog partitions.</p>
    /// <p><i>Sample API Call</i>:</p>
    pub fn expression(&self) -> ::std::option::Option<&str> {
        self.expression.as_deref()
    }
    /// <p>A continuation token, if this is not the first call to retrieve these partitions.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The segment of the table's partitions to scan in this request.</p>
    pub fn segment(&self) -> ::std::option::Option<&crate::types::Segment> {
        self.segment.as_ref()
    }
    /// <p>The maximum number of partitions to return in a single response.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>When true, specifies not returning the partition column schema. Useful when you are interested only in other partition attributes such as partition values or location. This approach avoids the problem of a large response by not returning duplicate data.</p>
    pub fn exclude_column_schema(&self) -> ::std::option::Option<bool> {
        self.exclude_column_schema
    }
    /// <p>The transaction ID at which to read the partition contents.</p>
    pub fn transaction_id(&self) -> ::std::option::Option<&str> {
        self.transaction_id.as_deref()
    }
    /// <p>The time as of when to read the partition contents. If not set, the most recent transaction commit time will be used. Cannot be specified along with <code>TransactionId</code>.</p>
    pub fn query_as_of_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.query_as_of_time.as_ref()
    }
}
impl GetPartitionsInput {
    /// Creates a new builder-style object to manufacture [`GetPartitionsInput`](crate::operation::get_partitions::GetPartitionsInput).
    pub fn builder() -> crate::operation::get_partitions::builders::GetPartitionsInputBuilder {
        crate::operation::get_partitions::builders::GetPartitionsInputBuilder::default()
    }
}

/// A builder for [`GetPartitionsInput`](crate::operation::get_partitions::GetPartitionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetPartitionsInputBuilder {
    pub(crate) catalog_id: ::std::option::Option<::std::string::String>,
    pub(crate) database_name: ::std::option::Option<::std::string::String>,
    pub(crate) table_name: ::std::option::Option<::std::string::String>,
    pub(crate) expression: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) segment: ::std::option::Option<crate::types::Segment>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) exclude_column_schema: ::std::option::Option<bool>,
    pub(crate) transaction_id: ::std::option::Option<::std::string::String>,
    pub(crate) query_as_of_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl GetPartitionsInputBuilder {
    /// <p>The ID of the Data Catalog where the partitions in question reside. If none is provided, the Amazon Web Services account ID is used by default.</p>
    pub fn catalog_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.catalog_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Data Catalog where the partitions in question reside. If none is provided, the Amazon Web Services account ID is used by default.</p>
    pub fn set_catalog_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.catalog_id = input;
        self
    }
    /// <p>The ID of the Data Catalog where the partitions in question reside. If none is provided, the Amazon Web Services account ID is used by default.</p>
    pub fn get_catalog_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.catalog_id
    }
    /// <p>The name of the catalog database where the partitions reside.</p>
    /// This field is required.
    pub fn database_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.database_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the catalog database where the partitions reside.</p>
    pub fn set_database_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.database_name = input;
        self
    }
    /// <p>The name of the catalog database where the partitions reside.</p>
    pub fn get_database_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.database_name
    }
    /// <p>The name of the partitions' table.</p>
    /// This field is required.
    pub fn table_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.table_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the partitions' table.</p>
    pub fn set_table_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.table_name = input;
        self
    }
    /// <p>The name of the partitions' table.</p>
    pub fn get_table_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.table_name
    }
    /// <p>An expression that filters the partitions to be returned.</p>
    /// <p>The expression uses SQL syntax similar to the SQL <code>WHERE</code> filter clause. The SQL statement parser <a href="http://jsqlparser.sourceforge.net/home.php">JSQLParser</a> parses the expression.</p>
    /// <p><i>Operators</i>: The following are the operators that you can use in the <code>Expression</code> API call:</p>
    /// <dl>
    /// <dt>
    /// =
    /// </dt>
    /// <dd>
    /// <p>Checks whether the values of the two operands are equal; if yes, then the condition becomes true.</p>
    /// <p>Example: Assume 'variable a' holds 10 and 'variable b' holds 20.</p>
    /// <p>(a = b) is not true.</p>
    /// </dd>
    /// <dt>
    /// &lt; &gt;
    /// </dt>
    /// <dd>
    /// <p>Checks whether the values of two operands are equal; if the values are not equal, then the condition becomes true.</p>
    /// <p>Example: (a &lt; &gt; b) is true.</p>
    /// </dd>
    /// <dt>
    /// &gt;
    /// </dt>
    /// <dd>
    /// <p>Checks whether the value of the left operand is greater than the value of the right operand; if yes, then the condition becomes true.</p>
    /// <p>Example: (a &gt; b) is not true.</p>
    /// </dd>
    /// <dt>
    /// &lt;
    /// </dt>
    /// <dd>
    /// <p>Checks whether the value of the left operand is less than the value of the right operand; if yes, then the condition becomes true.</p>
    /// <p>Example: (a &lt; b) is true.</p>
    /// </dd>
    /// <dt>
    /// &gt;=
    /// </dt>
    /// <dd>
    /// <p>Checks whether the value of the left operand is greater than or equal to the value of the right operand; if yes, then the condition becomes true.</p>
    /// <p>Example: (a &gt;= b) is not true.</p>
    /// </dd>
    /// <dt>
    /// &lt;=
    /// </dt>
    /// <dd>
    /// <p>Checks whether the value of the left operand is less than or equal to the value of the right operand; if yes, then the condition becomes true.</p>
    /// <p>Example: (a &lt;= b) is true.</p>
    /// </dd>
    /// <dt>
    /// AND, OR, IN, BETWEEN, LIKE, NOT, IS NULL
    /// </dt>
    /// <dd>
    /// <p>Logical operators.</p>
    /// </dd>
    /// </dl>
    /// <p><i>Supported Partition Key Types</i>: The following are the supported partition keys.</p>
    /// <ul>
    /// <li>
    /// <p><code>string</code></p></li>
    /// <li>
    /// <p><code>date</code></p></li>
    /// <li>
    /// <p><code>timestamp</code></p></li>
    /// <li>
    /// <p><code>int</code></p></li>
    /// <li>
    /// <p><code>bigint</code></p></li>
    /// <li>
    /// <p><code>long</code></p></li>
    /// <li>
    /// <p><code>tinyint</code></p></li>
    /// <li>
    /// <p><code>smallint</code></p></li>
    /// <li>
    /// <p><code>decimal</code></p></li>
    /// </ul>
    /// <p>If an type is encountered that is not valid, an exception is thrown.</p>
    /// <p>The following list shows the valid operators on each type. When you define a crawler, the <code>partitionKey</code> type is created as a <code>STRING</code>, to be compatible with the catalog partitions.</p>
    /// <p><i>Sample API Call</i>:</p>
    pub fn expression(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.expression = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An expression that filters the partitions to be returned.</p>
    /// <p>The expression uses SQL syntax similar to the SQL <code>WHERE</code> filter clause. The SQL statement parser <a href="http://jsqlparser.sourceforge.net/home.php">JSQLParser</a> parses the expression.</p>
    /// <p><i>Operators</i>: The following are the operators that you can use in the <code>Expression</code> API call:</p>
    /// <dl>
    /// <dt>
    /// =
    /// </dt>
    /// <dd>
    /// <p>Checks whether the values of the two operands are equal; if yes, then the condition becomes true.</p>
    /// <p>Example: Assume 'variable a' holds 10 and 'variable b' holds 20.</p>
    /// <p>(a = b) is not true.</p>
    /// </dd>
    /// <dt>
    /// &lt; &gt;
    /// </dt>
    /// <dd>
    /// <p>Checks whether the values of two operands are equal; if the values are not equal, then the condition becomes true.</p>
    /// <p>Example: (a &lt; &gt; b) is true.</p>
    /// </dd>
    /// <dt>
    /// &gt;
    /// </dt>
    /// <dd>
    /// <p>Checks whether the value of the left operand is greater than the value of the right operand; if yes, then the condition becomes true.</p>
    /// <p>Example: (a &gt; b) is not true.</p>
    /// </dd>
    /// <dt>
    /// &lt;
    /// </dt>
    /// <dd>
    /// <p>Checks whether the value of the left operand is less than the value of the right operand; if yes, then the condition becomes true.</p>
    /// <p>Example: (a &lt; b) is true.</p>
    /// </dd>
    /// <dt>
    /// &gt;=
    /// </dt>
    /// <dd>
    /// <p>Checks whether the value of the left operand is greater than or equal to the value of the right operand; if yes, then the condition becomes true.</p>
    /// <p>Example: (a &gt;= b) is not true.</p>
    /// </dd>
    /// <dt>
    /// &lt;=
    /// </dt>
    /// <dd>
    /// <p>Checks whether the value of the left operand is less than or equal to the value of the right operand; if yes, then the condition becomes true.</p>
    /// <p>Example: (a &lt;= b) is true.</p>
    /// </dd>
    /// <dt>
    /// AND, OR, IN, BETWEEN, LIKE, NOT, IS NULL
    /// </dt>
    /// <dd>
    /// <p>Logical operators.</p>
    /// </dd>
    /// </dl>
    /// <p><i>Supported Partition Key Types</i>: The following are the supported partition keys.</p>
    /// <ul>
    /// <li>
    /// <p><code>string</code></p></li>
    /// <li>
    /// <p><code>date</code></p></li>
    /// <li>
    /// <p><code>timestamp</code></p></li>
    /// <li>
    /// <p><code>int</code></p></li>
    /// <li>
    /// <p><code>bigint</code></p></li>
    /// <li>
    /// <p><code>long</code></p></li>
    /// <li>
    /// <p><code>tinyint</code></p></li>
    /// <li>
    /// <p><code>smallint</code></p></li>
    /// <li>
    /// <p><code>decimal</code></p></li>
    /// </ul>
    /// <p>If an type is encountered that is not valid, an exception is thrown.</p>
    /// <p>The following list shows the valid operators on each type. When you define a crawler, the <code>partitionKey</code> type is created as a <code>STRING</code>, to be compatible with the catalog partitions.</p>
    /// <p><i>Sample API Call</i>:</p>
    pub fn set_expression(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.expression = input;
        self
    }
    /// <p>An expression that filters the partitions to be returned.</p>
    /// <p>The expression uses SQL syntax similar to the SQL <code>WHERE</code> filter clause. The SQL statement parser <a href="http://jsqlparser.sourceforge.net/home.php">JSQLParser</a> parses the expression.</p>
    /// <p><i>Operators</i>: The following are the operators that you can use in the <code>Expression</code> API call:</p>
    /// <dl>
    /// <dt>
    /// =
    /// </dt>
    /// <dd>
    /// <p>Checks whether the values of the two operands are equal; if yes, then the condition becomes true.</p>
    /// <p>Example: Assume 'variable a' holds 10 and 'variable b' holds 20.</p>
    /// <p>(a = b) is not true.</p>
    /// </dd>
    /// <dt>
    /// &lt; &gt;
    /// </dt>
    /// <dd>
    /// <p>Checks whether the values of two operands are equal; if the values are not equal, then the condition becomes true.</p>
    /// <p>Example: (a &lt; &gt; b) is true.</p>
    /// </dd>
    /// <dt>
    /// &gt;
    /// </dt>
    /// <dd>
    /// <p>Checks whether the value of the left operand is greater than the value of the right operand; if yes, then the condition becomes true.</p>
    /// <p>Example: (a &gt; b) is not true.</p>
    /// </dd>
    /// <dt>
    /// &lt;
    /// </dt>
    /// <dd>
    /// <p>Checks whether the value of the left operand is less than the value of the right operand; if yes, then the condition becomes true.</p>
    /// <p>Example: (a &lt; b) is true.</p>
    /// </dd>
    /// <dt>
    /// &gt;=
    /// </dt>
    /// <dd>
    /// <p>Checks whether the value of the left operand is greater than or equal to the value of the right operand; if yes, then the condition becomes true.</p>
    /// <p>Example: (a &gt;= b) is not true.</p>
    /// </dd>
    /// <dt>
    /// &lt;=
    /// </dt>
    /// <dd>
    /// <p>Checks whether the value of the left operand is less than or equal to the value of the right operand; if yes, then the condition becomes true.</p>
    /// <p>Example: (a &lt;= b) is true.</p>
    /// </dd>
    /// <dt>
    /// AND, OR, IN, BETWEEN, LIKE, NOT, IS NULL
    /// </dt>
    /// <dd>
    /// <p>Logical operators.</p>
    /// </dd>
    /// </dl>
    /// <p><i>Supported Partition Key Types</i>: The following are the supported partition keys.</p>
    /// <ul>
    /// <li>
    /// <p><code>string</code></p></li>
    /// <li>
    /// <p><code>date</code></p></li>
    /// <li>
    /// <p><code>timestamp</code></p></li>
    /// <li>
    /// <p><code>int</code></p></li>
    /// <li>
    /// <p><code>bigint</code></p></li>
    /// <li>
    /// <p><code>long</code></p></li>
    /// <li>
    /// <p><code>tinyint</code></p></li>
    /// <li>
    /// <p><code>smallint</code></p></li>
    /// <li>
    /// <p><code>decimal</code></p></li>
    /// </ul>
    /// <p>If an type is encountered that is not valid, an exception is thrown.</p>
    /// <p>The following list shows the valid operators on each type. When you define a crawler, the <code>partitionKey</code> type is created as a <code>STRING</code>, to be compatible with the catalog partitions.</p>
    /// <p><i>Sample API Call</i>:</p>
    pub fn get_expression(&self) -> &::std::option::Option<::std::string::String> {
        &self.expression
    }
    /// <p>A continuation token, if this is not the first call to retrieve these partitions.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A continuation token, if this is not the first call to retrieve these partitions.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A continuation token, if this is not the first call to retrieve these partitions.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The segment of the table's partitions to scan in this request.</p>
    pub fn segment(mut self, input: crate::types::Segment) -> Self {
        self.segment = ::std::option::Option::Some(input);
        self
    }
    /// <p>The segment of the table's partitions to scan in this request.</p>
    pub fn set_segment(mut self, input: ::std::option::Option<crate::types::Segment>) -> Self {
        self.segment = input;
        self
    }
    /// <p>The segment of the table's partitions to scan in this request.</p>
    pub fn get_segment(&self) -> &::std::option::Option<crate::types::Segment> {
        &self.segment
    }
    /// <p>The maximum number of partitions to return in a single response.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of partitions to return in a single response.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of partitions to return in a single response.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>When true, specifies not returning the partition column schema. Useful when you are interested only in other partition attributes such as partition values or location. This approach avoids the problem of a large response by not returning duplicate data.</p>
    pub fn exclude_column_schema(mut self, input: bool) -> Self {
        self.exclude_column_schema = ::std::option::Option::Some(input);
        self
    }
    /// <p>When true, specifies not returning the partition column schema. Useful when you are interested only in other partition attributes such as partition values or location. This approach avoids the problem of a large response by not returning duplicate data.</p>
    pub fn set_exclude_column_schema(mut self, input: ::std::option::Option<bool>) -> Self {
        self.exclude_column_schema = input;
        self
    }
    /// <p>When true, specifies not returning the partition column schema. Useful when you are interested only in other partition attributes such as partition values or location. This approach avoids the problem of a large response by not returning duplicate data.</p>
    pub fn get_exclude_column_schema(&self) -> &::std::option::Option<bool> {
        &self.exclude_column_schema
    }
    /// <p>The transaction ID at which to read the partition contents.</p>
    pub fn transaction_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.transaction_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The transaction ID at which to read the partition contents.</p>
    pub fn set_transaction_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.transaction_id = input;
        self
    }
    /// <p>The transaction ID at which to read the partition contents.</p>
    pub fn get_transaction_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.transaction_id
    }
    /// <p>The time as of when to read the partition contents. If not set, the most recent transaction commit time will be used. Cannot be specified along with <code>TransactionId</code>.</p>
    pub fn query_as_of_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.query_as_of_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time as of when to read the partition contents. If not set, the most recent transaction commit time will be used. Cannot be specified along with <code>TransactionId</code>.</p>
    pub fn set_query_as_of_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.query_as_of_time = input;
        self
    }
    /// <p>The time as of when to read the partition contents. If not set, the most recent transaction commit time will be used. Cannot be specified along with <code>TransactionId</code>.</p>
    pub fn get_query_as_of_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.query_as_of_time
    }
    /// Consumes the builder and constructs a [`GetPartitionsInput`](crate::operation::get_partitions::GetPartitionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_partitions::GetPartitionsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_partitions::GetPartitionsInput {
            catalog_id: self.catalog_id,
            database_name: self.database_name,
            table_name: self.table_name,
            expression: self.expression,
            next_token: self.next_token,
            segment: self.segment,
            max_results: self.max_results,
            exclude_column_schema: self.exclude_column_schema,
            transaction_id: self.transaction_id,
            query_as_of_time: self.query_as_of_time,
        })
    }
}
