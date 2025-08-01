// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListServersInput {
    /// <p>Criteria for filtering servers.</p>
    pub server_criteria: ::std::option::Option<crate::types::ServerCriteria>,
    /// <p>Specifies the filter value, which is based on the type of server criteria. For example, if <code>serverCriteria</code> is <code>OS_NAME</code>, and the <code>filterValue</code> is equal to <code>WindowsServer</code>, then <code>ListServers</code> returns all of the servers matching the OS name <code>WindowsServer</code>.</p>
    pub filter_value: ::std::option::Option<::std::string::String>,
    /// <p>Specifies whether to sort by ascending (<code>ASC</code>) or descending (<code>DESC</code>) order.</p>
    pub sort: ::std::option::Option<crate::types::SortOrder>,
    /// <p>Specifies the group ID to filter on.</p>
    pub group_id_filter: ::std::option::Option<::std::vec::Vec<crate::types::Group>>,
    /// <p>The token from a previous call that you use to retrieve the next set of results. For example, if a previous call to this action returned 100 items, but you set <code>maxResults</code> to 10. You'll receive a set of 10 results along with a token. You then use the returned token to retrieve the next set of 10.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of items to include in the response. The maximum value is 100.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListServersInput {
    /// <p>Criteria for filtering servers.</p>
    pub fn server_criteria(&self) -> ::std::option::Option<&crate::types::ServerCriteria> {
        self.server_criteria.as_ref()
    }
    /// <p>Specifies the filter value, which is based on the type of server criteria. For example, if <code>serverCriteria</code> is <code>OS_NAME</code>, and the <code>filterValue</code> is equal to <code>WindowsServer</code>, then <code>ListServers</code> returns all of the servers matching the OS name <code>WindowsServer</code>.</p>
    pub fn filter_value(&self) -> ::std::option::Option<&str> {
        self.filter_value.as_deref()
    }
    /// <p>Specifies whether to sort by ascending (<code>ASC</code>) or descending (<code>DESC</code>) order.</p>
    pub fn sort(&self) -> ::std::option::Option<&crate::types::SortOrder> {
        self.sort.as_ref()
    }
    /// <p>Specifies the group ID to filter on.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.group_id_filter.is_none()`.
    pub fn group_id_filter(&self) -> &[crate::types::Group] {
        self.group_id_filter.as_deref().unwrap_or_default()
    }
    /// <p>The token from a previous call that you use to retrieve the next set of results. For example, if a previous call to this action returned 100 items, but you set <code>maxResults</code> to 10. You'll receive a set of 10 results along with a token. You then use the returned token to retrieve the next set of 10.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of items to include in the response. The maximum value is 100.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListServersInput {
    /// Creates a new builder-style object to manufacture [`ListServersInput`](crate::operation::list_servers::ListServersInput).
    pub fn builder() -> crate::operation::list_servers::builders::ListServersInputBuilder {
        crate::operation::list_servers::builders::ListServersInputBuilder::default()
    }
}

/// A builder for [`ListServersInput`](crate::operation::list_servers::ListServersInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListServersInputBuilder {
    pub(crate) server_criteria: ::std::option::Option<crate::types::ServerCriteria>,
    pub(crate) filter_value: ::std::option::Option<::std::string::String>,
    pub(crate) sort: ::std::option::Option<crate::types::SortOrder>,
    pub(crate) group_id_filter: ::std::option::Option<::std::vec::Vec<crate::types::Group>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListServersInputBuilder {
    /// <p>Criteria for filtering servers.</p>
    pub fn server_criteria(mut self, input: crate::types::ServerCriteria) -> Self {
        self.server_criteria = ::std::option::Option::Some(input);
        self
    }
    /// <p>Criteria for filtering servers.</p>
    pub fn set_server_criteria(mut self, input: ::std::option::Option<crate::types::ServerCriteria>) -> Self {
        self.server_criteria = input;
        self
    }
    /// <p>Criteria for filtering servers.</p>
    pub fn get_server_criteria(&self) -> &::std::option::Option<crate::types::ServerCriteria> {
        &self.server_criteria
    }
    /// <p>Specifies the filter value, which is based on the type of server criteria. For example, if <code>serverCriteria</code> is <code>OS_NAME</code>, and the <code>filterValue</code> is equal to <code>WindowsServer</code>, then <code>ListServers</code> returns all of the servers matching the OS name <code>WindowsServer</code>.</p>
    pub fn filter_value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.filter_value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the filter value, which is based on the type of server criteria. For example, if <code>serverCriteria</code> is <code>OS_NAME</code>, and the <code>filterValue</code> is equal to <code>WindowsServer</code>, then <code>ListServers</code> returns all of the servers matching the OS name <code>WindowsServer</code>.</p>
    pub fn set_filter_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.filter_value = input;
        self
    }
    /// <p>Specifies the filter value, which is based on the type of server criteria. For example, if <code>serverCriteria</code> is <code>OS_NAME</code>, and the <code>filterValue</code> is equal to <code>WindowsServer</code>, then <code>ListServers</code> returns all of the servers matching the OS name <code>WindowsServer</code>.</p>
    pub fn get_filter_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.filter_value
    }
    /// <p>Specifies whether to sort by ascending (<code>ASC</code>) or descending (<code>DESC</code>) order.</p>
    pub fn sort(mut self, input: crate::types::SortOrder) -> Self {
        self.sort = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether to sort by ascending (<code>ASC</code>) or descending (<code>DESC</code>) order.</p>
    pub fn set_sort(mut self, input: ::std::option::Option<crate::types::SortOrder>) -> Self {
        self.sort = input;
        self
    }
    /// <p>Specifies whether to sort by ascending (<code>ASC</code>) or descending (<code>DESC</code>) order.</p>
    pub fn get_sort(&self) -> &::std::option::Option<crate::types::SortOrder> {
        &self.sort
    }
    /// Appends an item to `group_id_filter`.
    ///
    /// To override the contents of this collection use [`set_group_id_filter`](Self::set_group_id_filter).
    ///
    /// <p>Specifies the group ID to filter on.</p>
    pub fn group_id_filter(mut self, input: crate::types::Group) -> Self {
        let mut v = self.group_id_filter.unwrap_or_default();
        v.push(input);
        self.group_id_filter = ::std::option::Option::Some(v);
        self
    }
    /// <p>Specifies the group ID to filter on.</p>
    pub fn set_group_id_filter(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Group>>) -> Self {
        self.group_id_filter = input;
        self
    }
    /// <p>Specifies the group ID to filter on.</p>
    pub fn get_group_id_filter(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Group>> {
        &self.group_id_filter
    }
    /// <p>The token from a previous call that you use to retrieve the next set of results. For example, if a previous call to this action returned 100 items, but you set <code>maxResults</code> to 10. You'll receive a set of 10 results along with a token. You then use the returned token to retrieve the next set of 10.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token from a previous call that you use to retrieve the next set of results. For example, if a previous call to this action returned 100 items, but you set <code>maxResults</code> to 10. You'll receive a set of 10 results along with a token. You then use the returned token to retrieve the next set of 10.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token from a previous call that you use to retrieve the next set of results. For example, if a previous call to this action returned 100 items, but you set <code>maxResults</code> to 10. You'll receive a set of 10 results along with a token. You then use the returned token to retrieve the next set of 10.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of items to include in the response. The maximum value is 100.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of items to include in the response. The maximum value is 100.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of items to include in the response. The maximum value is 100.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListServersInput`](crate::operation::list_servers::ListServersInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::list_servers::ListServersInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_servers::ListServersInput {
            server_criteria: self.server_criteria,
            filter_value: self.filter_value,
            sort: self.sort,
            group_id_filter: self.group_id_filter,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
