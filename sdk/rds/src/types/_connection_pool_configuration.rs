// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the settings that control the size and behavior of the connection pool associated with a <code>DBProxyTargetGroup</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ConnectionPoolConfiguration {
    /// <p>The maximum size of the connection pool for each target in a target group. The value is expressed as a percentage of the <code>max_connections</code> setting for the RDS DB instance or Aurora DB cluster used by the target group.</p>
    /// <p>If you specify <code>MaxIdleConnectionsPercent</code>, then you must also include a value for this parameter.</p>
    /// <p>Default: <code>10</code> for RDS for Microsoft SQL Server, and <code>100</code> for all other engines</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must be between 1 and 100.</p></li>
    /// </ul>
    pub max_connections_percent: ::std::option::Option<i32>,
    /// <p>A value that controls how actively the proxy closes idle database connections in the connection pool. The value is expressed as a percentage of the <code>max_connections</code> setting for the RDS DB instance or Aurora DB cluster used by the target group. With a high value, the proxy leaves a high percentage of idle database connections open. A low value causes the proxy to close more idle connections and return them to the database.</p>
    /// <p>If you specify this parameter, then you must also include a value for <code>MaxConnectionsPercent</code>.</p>
    /// <p>Default: The default value is half of the value of <code>MaxConnectionsPercent</code>. For example, if <code>MaxConnectionsPercent</code> is 80, then the default value of <code>MaxIdleConnectionsPercent</code> is 40. If the value of <code>MaxConnectionsPercent</code> isn't specified, then for SQL Server, <code>MaxIdleConnectionsPercent</code> is <code>5</code>, and for all other engines, the default is <code>50</code>.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must be between 0 and the value of <code>MaxConnectionsPercent</code>.</p></li>
    /// </ul>
    pub max_idle_connections_percent: ::std::option::Option<i32>,
    /// <p>The number of seconds for a proxy to wait for a connection to become available in the connection pool. This setting only applies when the proxy has opened its maximum number of connections and all connections are busy with client sessions.</p>
    /// <p>Default: <code>120</code></p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must be between 0 and 300.</p></li>
    /// </ul>
    pub connection_borrow_timeout: ::std::option::Option<i32>,
    /// <p>Each item in the list represents a class of SQL operations that normally cause all later statements in a session using a proxy to be pinned to the same underlying database connection. Including an item in the list exempts that class of SQL operations from the pinning behavior.</p>
    /// <p>Default: no session pinning filters</p>
    pub session_pinning_filters: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Add an initialization query, or modify the current one. You can specify one or more SQL statements for the proxy to run when opening each new database connection. The setting is typically used with <code>SET</code> statements to make sure that each connection has identical settings. Make sure the query added here is valid. This is an optional field, so you can choose to leave it empty. For including multiple variables in a single SET statement, use a comma separator.</p>
    /// <p>For example: <code>SET variable1=value1, variable2=value2</code></p>
    /// <p>Default: no initialization query</p><important>
    /// <p>Since you can access initialization query as part of target group configuration, it is not protected by authentication or cryptographic methods. Anyone with access to view or manage your proxy target group configuration can view the initialization query. You should not add sensitive data, such as passwords or long-lived encryption keys, to this option.</p>
    /// </important>
    pub init_query: ::std::option::Option<::std::string::String>,
}
impl ConnectionPoolConfiguration {
    /// <p>The maximum size of the connection pool for each target in a target group. The value is expressed as a percentage of the <code>max_connections</code> setting for the RDS DB instance or Aurora DB cluster used by the target group.</p>
    /// <p>If you specify <code>MaxIdleConnectionsPercent</code>, then you must also include a value for this parameter.</p>
    /// <p>Default: <code>10</code> for RDS for Microsoft SQL Server, and <code>100</code> for all other engines</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must be between 1 and 100.</p></li>
    /// </ul>
    pub fn max_connections_percent(&self) -> ::std::option::Option<i32> {
        self.max_connections_percent
    }
    /// <p>A value that controls how actively the proxy closes idle database connections in the connection pool. The value is expressed as a percentage of the <code>max_connections</code> setting for the RDS DB instance or Aurora DB cluster used by the target group. With a high value, the proxy leaves a high percentage of idle database connections open. A low value causes the proxy to close more idle connections and return them to the database.</p>
    /// <p>If you specify this parameter, then you must also include a value for <code>MaxConnectionsPercent</code>.</p>
    /// <p>Default: The default value is half of the value of <code>MaxConnectionsPercent</code>. For example, if <code>MaxConnectionsPercent</code> is 80, then the default value of <code>MaxIdleConnectionsPercent</code> is 40. If the value of <code>MaxConnectionsPercent</code> isn't specified, then for SQL Server, <code>MaxIdleConnectionsPercent</code> is <code>5</code>, and for all other engines, the default is <code>50</code>.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must be between 0 and the value of <code>MaxConnectionsPercent</code>.</p></li>
    /// </ul>
    pub fn max_idle_connections_percent(&self) -> ::std::option::Option<i32> {
        self.max_idle_connections_percent
    }
    /// <p>The number of seconds for a proxy to wait for a connection to become available in the connection pool. This setting only applies when the proxy has opened its maximum number of connections and all connections are busy with client sessions.</p>
    /// <p>Default: <code>120</code></p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must be between 0 and 300.</p></li>
    /// </ul>
    pub fn connection_borrow_timeout(&self) -> ::std::option::Option<i32> {
        self.connection_borrow_timeout
    }
    /// <p>Each item in the list represents a class of SQL operations that normally cause all later statements in a session using a proxy to be pinned to the same underlying database connection. Including an item in the list exempts that class of SQL operations from the pinning behavior.</p>
    /// <p>Default: no session pinning filters</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.session_pinning_filters.is_none()`.
    pub fn session_pinning_filters(&self) -> &[::std::string::String] {
        self.session_pinning_filters.as_deref().unwrap_or_default()
    }
    /// <p>Add an initialization query, or modify the current one. You can specify one or more SQL statements for the proxy to run when opening each new database connection. The setting is typically used with <code>SET</code> statements to make sure that each connection has identical settings. Make sure the query added here is valid. This is an optional field, so you can choose to leave it empty. For including multiple variables in a single SET statement, use a comma separator.</p>
    /// <p>For example: <code>SET variable1=value1, variable2=value2</code></p>
    /// <p>Default: no initialization query</p><important>
    /// <p>Since you can access initialization query as part of target group configuration, it is not protected by authentication or cryptographic methods. Anyone with access to view or manage your proxy target group configuration can view the initialization query. You should not add sensitive data, such as passwords or long-lived encryption keys, to this option.</p>
    /// </important>
    pub fn init_query(&self) -> ::std::option::Option<&str> {
        self.init_query.as_deref()
    }
}
impl ConnectionPoolConfiguration {
    /// Creates a new builder-style object to manufacture [`ConnectionPoolConfiguration`](crate::types::ConnectionPoolConfiguration).
    pub fn builder() -> crate::types::builders::ConnectionPoolConfigurationBuilder {
        crate::types::builders::ConnectionPoolConfigurationBuilder::default()
    }
}

/// A builder for [`ConnectionPoolConfiguration`](crate::types::ConnectionPoolConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConnectionPoolConfigurationBuilder {
    pub(crate) max_connections_percent: ::std::option::Option<i32>,
    pub(crate) max_idle_connections_percent: ::std::option::Option<i32>,
    pub(crate) connection_borrow_timeout: ::std::option::Option<i32>,
    pub(crate) session_pinning_filters: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) init_query: ::std::option::Option<::std::string::String>,
}
impl ConnectionPoolConfigurationBuilder {
    /// <p>The maximum size of the connection pool for each target in a target group. The value is expressed as a percentage of the <code>max_connections</code> setting for the RDS DB instance or Aurora DB cluster used by the target group.</p>
    /// <p>If you specify <code>MaxIdleConnectionsPercent</code>, then you must also include a value for this parameter.</p>
    /// <p>Default: <code>10</code> for RDS for Microsoft SQL Server, and <code>100</code> for all other engines</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must be between 1 and 100.</p></li>
    /// </ul>
    pub fn max_connections_percent(mut self, input: i32) -> Self {
        self.max_connections_percent = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum size of the connection pool for each target in a target group. The value is expressed as a percentage of the <code>max_connections</code> setting for the RDS DB instance or Aurora DB cluster used by the target group.</p>
    /// <p>If you specify <code>MaxIdleConnectionsPercent</code>, then you must also include a value for this parameter.</p>
    /// <p>Default: <code>10</code> for RDS for Microsoft SQL Server, and <code>100</code> for all other engines</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must be between 1 and 100.</p></li>
    /// </ul>
    pub fn set_max_connections_percent(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_connections_percent = input;
        self
    }
    /// <p>The maximum size of the connection pool for each target in a target group. The value is expressed as a percentage of the <code>max_connections</code> setting for the RDS DB instance or Aurora DB cluster used by the target group.</p>
    /// <p>If you specify <code>MaxIdleConnectionsPercent</code>, then you must also include a value for this parameter.</p>
    /// <p>Default: <code>10</code> for RDS for Microsoft SQL Server, and <code>100</code> for all other engines</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must be between 1 and 100.</p></li>
    /// </ul>
    pub fn get_max_connections_percent(&self) -> &::std::option::Option<i32> {
        &self.max_connections_percent
    }
    /// <p>A value that controls how actively the proxy closes idle database connections in the connection pool. The value is expressed as a percentage of the <code>max_connections</code> setting for the RDS DB instance or Aurora DB cluster used by the target group. With a high value, the proxy leaves a high percentage of idle database connections open. A low value causes the proxy to close more idle connections and return them to the database.</p>
    /// <p>If you specify this parameter, then you must also include a value for <code>MaxConnectionsPercent</code>.</p>
    /// <p>Default: The default value is half of the value of <code>MaxConnectionsPercent</code>. For example, if <code>MaxConnectionsPercent</code> is 80, then the default value of <code>MaxIdleConnectionsPercent</code> is 40. If the value of <code>MaxConnectionsPercent</code> isn't specified, then for SQL Server, <code>MaxIdleConnectionsPercent</code> is <code>5</code>, and for all other engines, the default is <code>50</code>.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must be between 0 and the value of <code>MaxConnectionsPercent</code>.</p></li>
    /// </ul>
    pub fn max_idle_connections_percent(mut self, input: i32) -> Self {
        self.max_idle_connections_percent = ::std::option::Option::Some(input);
        self
    }
    /// <p>A value that controls how actively the proxy closes idle database connections in the connection pool. The value is expressed as a percentage of the <code>max_connections</code> setting for the RDS DB instance or Aurora DB cluster used by the target group. With a high value, the proxy leaves a high percentage of idle database connections open. A low value causes the proxy to close more idle connections and return them to the database.</p>
    /// <p>If you specify this parameter, then you must also include a value for <code>MaxConnectionsPercent</code>.</p>
    /// <p>Default: The default value is half of the value of <code>MaxConnectionsPercent</code>. For example, if <code>MaxConnectionsPercent</code> is 80, then the default value of <code>MaxIdleConnectionsPercent</code> is 40. If the value of <code>MaxConnectionsPercent</code> isn't specified, then for SQL Server, <code>MaxIdleConnectionsPercent</code> is <code>5</code>, and for all other engines, the default is <code>50</code>.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must be between 0 and the value of <code>MaxConnectionsPercent</code>.</p></li>
    /// </ul>
    pub fn set_max_idle_connections_percent(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_idle_connections_percent = input;
        self
    }
    /// <p>A value that controls how actively the proxy closes idle database connections in the connection pool. The value is expressed as a percentage of the <code>max_connections</code> setting for the RDS DB instance or Aurora DB cluster used by the target group. With a high value, the proxy leaves a high percentage of idle database connections open. A low value causes the proxy to close more idle connections and return them to the database.</p>
    /// <p>If you specify this parameter, then you must also include a value for <code>MaxConnectionsPercent</code>.</p>
    /// <p>Default: The default value is half of the value of <code>MaxConnectionsPercent</code>. For example, if <code>MaxConnectionsPercent</code> is 80, then the default value of <code>MaxIdleConnectionsPercent</code> is 40. If the value of <code>MaxConnectionsPercent</code> isn't specified, then for SQL Server, <code>MaxIdleConnectionsPercent</code> is <code>5</code>, and for all other engines, the default is <code>50</code>.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must be between 0 and the value of <code>MaxConnectionsPercent</code>.</p></li>
    /// </ul>
    pub fn get_max_idle_connections_percent(&self) -> &::std::option::Option<i32> {
        &self.max_idle_connections_percent
    }
    /// <p>The number of seconds for a proxy to wait for a connection to become available in the connection pool. This setting only applies when the proxy has opened its maximum number of connections and all connections are busy with client sessions.</p>
    /// <p>Default: <code>120</code></p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must be between 0 and 300.</p></li>
    /// </ul>
    pub fn connection_borrow_timeout(mut self, input: i32) -> Self {
        self.connection_borrow_timeout = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of seconds for a proxy to wait for a connection to become available in the connection pool. This setting only applies when the proxy has opened its maximum number of connections and all connections are busy with client sessions.</p>
    /// <p>Default: <code>120</code></p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must be between 0 and 300.</p></li>
    /// </ul>
    pub fn set_connection_borrow_timeout(mut self, input: ::std::option::Option<i32>) -> Self {
        self.connection_borrow_timeout = input;
        self
    }
    /// <p>The number of seconds for a proxy to wait for a connection to become available in the connection pool. This setting only applies when the proxy has opened its maximum number of connections and all connections are busy with client sessions.</p>
    /// <p>Default: <code>120</code></p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must be between 0 and 300.</p></li>
    /// </ul>
    pub fn get_connection_borrow_timeout(&self) -> &::std::option::Option<i32> {
        &self.connection_borrow_timeout
    }
    /// Appends an item to `session_pinning_filters`.
    ///
    /// To override the contents of this collection use [`set_session_pinning_filters`](Self::set_session_pinning_filters).
    ///
    /// <p>Each item in the list represents a class of SQL operations that normally cause all later statements in a session using a proxy to be pinned to the same underlying database connection. Including an item in the list exempts that class of SQL operations from the pinning behavior.</p>
    /// <p>Default: no session pinning filters</p>
    pub fn session_pinning_filters(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.session_pinning_filters.unwrap_or_default();
        v.push(input.into());
        self.session_pinning_filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>Each item in the list represents a class of SQL operations that normally cause all later statements in a session using a proxy to be pinned to the same underlying database connection. Including an item in the list exempts that class of SQL operations from the pinning behavior.</p>
    /// <p>Default: no session pinning filters</p>
    pub fn set_session_pinning_filters(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.session_pinning_filters = input;
        self
    }
    /// <p>Each item in the list represents a class of SQL operations that normally cause all later statements in a session using a proxy to be pinned to the same underlying database connection. Including an item in the list exempts that class of SQL operations from the pinning behavior.</p>
    /// <p>Default: no session pinning filters</p>
    pub fn get_session_pinning_filters(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.session_pinning_filters
    }
    /// <p>Add an initialization query, or modify the current one. You can specify one or more SQL statements for the proxy to run when opening each new database connection. The setting is typically used with <code>SET</code> statements to make sure that each connection has identical settings. Make sure the query added here is valid. This is an optional field, so you can choose to leave it empty. For including multiple variables in a single SET statement, use a comma separator.</p>
    /// <p>For example: <code>SET variable1=value1, variable2=value2</code></p>
    /// <p>Default: no initialization query</p><important>
    /// <p>Since you can access initialization query as part of target group configuration, it is not protected by authentication or cryptographic methods. Anyone with access to view or manage your proxy target group configuration can view the initialization query. You should not add sensitive data, such as passwords or long-lived encryption keys, to this option.</p>
    /// </important>
    pub fn init_query(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.init_query = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Add an initialization query, or modify the current one. You can specify one or more SQL statements for the proxy to run when opening each new database connection. The setting is typically used with <code>SET</code> statements to make sure that each connection has identical settings. Make sure the query added here is valid. This is an optional field, so you can choose to leave it empty. For including multiple variables in a single SET statement, use a comma separator.</p>
    /// <p>For example: <code>SET variable1=value1, variable2=value2</code></p>
    /// <p>Default: no initialization query</p><important>
    /// <p>Since you can access initialization query as part of target group configuration, it is not protected by authentication or cryptographic methods. Anyone with access to view or manage your proxy target group configuration can view the initialization query. You should not add sensitive data, such as passwords or long-lived encryption keys, to this option.</p>
    /// </important>
    pub fn set_init_query(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.init_query = input;
        self
    }
    /// <p>Add an initialization query, or modify the current one. You can specify one or more SQL statements for the proxy to run when opening each new database connection. The setting is typically used with <code>SET</code> statements to make sure that each connection has identical settings. Make sure the query added here is valid. This is an optional field, so you can choose to leave it empty. For including multiple variables in a single SET statement, use a comma separator.</p>
    /// <p>For example: <code>SET variable1=value1, variable2=value2</code></p>
    /// <p>Default: no initialization query</p><important>
    /// <p>Since you can access initialization query as part of target group configuration, it is not protected by authentication or cryptographic methods. Anyone with access to view or manage your proxy target group configuration can view the initialization query. You should not add sensitive data, such as passwords or long-lived encryption keys, to this option.</p>
    /// </important>
    pub fn get_init_query(&self) -> &::std::option::Option<::std::string::String> {
        &self.init_query
    }
    /// Consumes the builder and constructs a [`ConnectionPoolConfiguration`](crate::types::ConnectionPoolConfiguration).
    pub fn build(self) -> crate::types::ConnectionPoolConfiguration {
        crate::types::ConnectionPoolConfiguration {
            max_connections_percent: self.max_connections_percent,
            max_idle_connections_percent: self.max_idle_connections_percent,
            connection_borrow_timeout: self.connection_borrow_timeout,
            session_pinning_filters: self.session_pinning_filters,
            init_query: self.init_query,
        }
    }
}
