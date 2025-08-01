// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeConnectionAliasesOutput {
    /// <p>Information about the specified connection aliases.</p>
    pub connection_aliases: ::std::option::Option<::std::vec::Vec<crate::types::ConnectionAlias>>,
    /// <p>The token to use to retrieve the next page of results. This value is null when there are no more results to return.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeConnectionAliasesOutput {
    /// <p>Information about the specified connection aliases.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.connection_aliases.is_none()`.
    pub fn connection_aliases(&self) -> &[crate::types::ConnectionAlias] {
        self.connection_aliases.as_deref().unwrap_or_default()
    }
    /// <p>The token to use to retrieve the next page of results. This value is null when there are no more results to return.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeConnectionAliasesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeConnectionAliasesOutput {
    /// Creates a new builder-style object to manufacture [`DescribeConnectionAliasesOutput`](crate::operation::describe_connection_aliases::DescribeConnectionAliasesOutput).
    pub fn builder() -> crate::operation::describe_connection_aliases::builders::DescribeConnectionAliasesOutputBuilder {
        crate::operation::describe_connection_aliases::builders::DescribeConnectionAliasesOutputBuilder::default()
    }
}

/// A builder for [`DescribeConnectionAliasesOutput`](crate::operation::describe_connection_aliases::DescribeConnectionAliasesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeConnectionAliasesOutputBuilder {
    pub(crate) connection_aliases: ::std::option::Option<::std::vec::Vec<crate::types::ConnectionAlias>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeConnectionAliasesOutputBuilder {
    /// Appends an item to `connection_aliases`.
    ///
    /// To override the contents of this collection use [`set_connection_aliases`](Self::set_connection_aliases).
    ///
    /// <p>Information about the specified connection aliases.</p>
    pub fn connection_aliases(mut self, input: crate::types::ConnectionAlias) -> Self {
        let mut v = self.connection_aliases.unwrap_or_default();
        v.push(input);
        self.connection_aliases = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the specified connection aliases.</p>
    pub fn set_connection_aliases(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ConnectionAlias>>) -> Self {
        self.connection_aliases = input;
        self
    }
    /// <p>Information about the specified connection aliases.</p>
    pub fn get_connection_aliases(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ConnectionAlias>> {
        &self.connection_aliases
    }
    /// <p>The token to use to retrieve the next page of results. This value is null when there are no more results to return.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to use to retrieve the next page of results. This value is null when there are no more results to return.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to use to retrieve the next page of results. This value is null when there are no more results to return.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeConnectionAliasesOutput`](crate::operation::describe_connection_aliases::DescribeConnectionAliasesOutput).
    pub fn build(self) -> crate::operation::describe_connection_aliases::DescribeConnectionAliasesOutput {
        crate::operation::describe_connection_aliases::DescribeConnectionAliasesOutput {
            connection_aliases: self.connection_aliases,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
