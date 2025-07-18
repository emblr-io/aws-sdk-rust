// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListServerNeighborsOutput {
    /// <p>List of distinct servers that are one hop away from the given server.</p>
    pub neighbors: ::std::vec::Vec<crate::types::NeighborConnectionDetail>,
    /// <p>Token to retrieve the next set of results. For example, if you specified 100 IDs for <code>ListServerNeighborsRequest$neighborConfigurationIds</code> but set <code>ListServerNeighborsRequest$maxResults</code> to 10, you received a set of 10 results along with this token. Use this token in the next query to retrieve the next set of 10.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>Count of distinct servers that are one hop away from the given server.</p>
    pub known_dependency_count: i64,
    _request_id: Option<String>,
}
impl ListServerNeighborsOutput {
    /// <p>List of distinct servers that are one hop away from the given server.</p>
    pub fn neighbors(&self) -> &[crate::types::NeighborConnectionDetail] {
        use std::ops::Deref;
        self.neighbors.deref()
    }
    /// <p>Token to retrieve the next set of results. For example, if you specified 100 IDs for <code>ListServerNeighborsRequest$neighborConfigurationIds</code> but set <code>ListServerNeighborsRequest$maxResults</code> to 10, you received a set of 10 results along with this token. Use this token in the next query to retrieve the next set of 10.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>Count of distinct servers that are one hop away from the given server.</p>
    pub fn known_dependency_count(&self) -> i64 {
        self.known_dependency_count
    }
}
impl ::aws_types::request_id::RequestId for ListServerNeighborsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListServerNeighborsOutput {
    /// Creates a new builder-style object to manufacture [`ListServerNeighborsOutput`](crate::operation::list_server_neighbors::ListServerNeighborsOutput).
    pub fn builder() -> crate::operation::list_server_neighbors::builders::ListServerNeighborsOutputBuilder {
        crate::operation::list_server_neighbors::builders::ListServerNeighborsOutputBuilder::default()
    }
}

/// A builder for [`ListServerNeighborsOutput`](crate::operation::list_server_neighbors::ListServerNeighborsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListServerNeighborsOutputBuilder {
    pub(crate) neighbors: ::std::option::Option<::std::vec::Vec<crate::types::NeighborConnectionDetail>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) known_dependency_count: ::std::option::Option<i64>,
    _request_id: Option<String>,
}
impl ListServerNeighborsOutputBuilder {
    /// Appends an item to `neighbors`.
    ///
    /// To override the contents of this collection use [`set_neighbors`](Self::set_neighbors).
    ///
    /// <p>List of distinct servers that are one hop away from the given server.</p>
    pub fn neighbors(mut self, input: crate::types::NeighborConnectionDetail) -> Self {
        let mut v = self.neighbors.unwrap_or_default();
        v.push(input);
        self.neighbors = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of distinct servers that are one hop away from the given server.</p>
    pub fn set_neighbors(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::NeighborConnectionDetail>>) -> Self {
        self.neighbors = input;
        self
    }
    /// <p>List of distinct servers that are one hop away from the given server.</p>
    pub fn get_neighbors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::NeighborConnectionDetail>> {
        &self.neighbors
    }
    /// <p>Token to retrieve the next set of results. For example, if you specified 100 IDs for <code>ListServerNeighborsRequest$neighborConfigurationIds</code> but set <code>ListServerNeighborsRequest$maxResults</code> to 10, you received a set of 10 results along with this token. Use this token in the next query to retrieve the next set of 10.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Token to retrieve the next set of results. For example, if you specified 100 IDs for <code>ListServerNeighborsRequest$neighborConfigurationIds</code> but set <code>ListServerNeighborsRequest$maxResults</code> to 10, you received a set of 10 results along with this token. Use this token in the next query to retrieve the next set of 10.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>Token to retrieve the next set of results. For example, if you specified 100 IDs for <code>ListServerNeighborsRequest$neighborConfigurationIds</code> but set <code>ListServerNeighborsRequest$maxResults</code> to 10, you received a set of 10 results along with this token. Use this token in the next query to retrieve the next set of 10.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>Count of distinct servers that are one hop away from the given server.</p>
    pub fn known_dependency_count(mut self, input: i64) -> Self {
        self.known_dependency_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>Count of distinct servers that are one hop away from the given server.</p>
    pub fn set_known_dependency_count(mut self, input: ::std::option::Option<i64>) -> Self {
        self.known_dependency_count = input;
        self
    }
    /// <p>Count of distinct servers that are one hop away from the given server.</p>
    pub fn get_known_dependency_count(&self) -> &::std::option::Option<i64> {
        &self.known_dependency_count
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListServerNeighborsOutput`](crate::operation::list_server_neighbors::ListServerNeighborsOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`neighbors`](crate::operation::list_server_neighbors::builders::ListServerNeighborsOutputBuilder::neighbors)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_server_neighbors::ListServerNeighborsOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_server_neighbors::ListServerNeighborsOutput {
            neighbors: self.neighbors.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "neighbors",
                    "neighbors was not specified but it is required when building ListServerNeighborsOutput",
                )
            })?,
            next_token: self.next_token,
            known_dependency_count: self.known_dependency_count.unwrap_or_default(),
            _request_id: self._request_id,
        })
    }
}
