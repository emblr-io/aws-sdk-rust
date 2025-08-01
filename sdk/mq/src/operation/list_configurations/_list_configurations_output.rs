// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListConfigurationsOutput {
    /// <p>The list of all revisions for the specified configuration.</p>
    pub configurations: ::std::option::Option<::std::vec::Vec<crate::types::Configuration>>,
    /// <p>The maximum number of configurations that Amazon MQ can return per page (20 by default). This value must be an integer from 5 to 100.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The token that specifies the next page of results Amazon MQ should return. To request the first page, leave nextToken empty.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListConfigurationsOutput {
    /// <p>The list of all revisions for the specified configuration.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.configurations.is_none()`.
    pub fn configurations(&self) -> &[crate::types::Configuration] {
        self.configurations.as_deref().unwrap_or_default()
    }
    /// <p>The maximum number of configurations that Amazon MQ can return per page (20 by default). This value must be an integer from 5 to 100.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The token that specifies the next page of results Amazon MQ should return. To request the first page, leave nextToken empty.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListConfigurationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListConfigurationsOutput {
    /// Creates a new builder-style object to manufacture [`ListConfigurationsOutput`](crate::operation::list_configurations::ListConfigurationsOutput).
    pub fn builder() -> crate::operation::list_configurations::builders::ListConfigurationsOutputBuilder {
        crate::operation::list_configurations::builders::ListConfigurationsOutputBuilder::default()
    }
}

/// A builder for [`ListConfigurationsOutput`](crate::operation::list_configurations::ListConfigurationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListConfigurationsOutputBuilder {
    pub(crate) configurations: ::std::option::Option<::std::vec::Vec<crate::types::Configuration>>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListConfigurationsOutputBuilder {
    /// Appends an item to `configurations`.
    ///
    /// To override the contents of this collection use [`set_configurations`](Self::set_configurations).
    ///
    /// <p>The list of all revisions for the specified configuration.</p>
    pub fn configurations(mut self, input: crate::types::Configuration) -> Self {
        let mut v = self.configurations.unwrap_or_default();
        v.push(input);
        self.configurations = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of all revisions for the specified configuration.</p>
    pub fn set_configurations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Configuration>>) -> Self {
        self.configurations = input;
        self
    }
    /// <p>The list of all revisions for the specified configuration.</p>
    pub fn get_configurations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Configuration>> {
        &self.configurations
    }
    /// <p>The maximum number of configurations that Amazon MQ can return per page (20 by default). This value must be an integer from 5 to 100.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of configurations that Amazon MQ can return per page (20 by default). This value must be an integer from 5 to 100.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of configurations that Amazon MQ can return per page (20 by default). This value must be an integer from 5 to 100.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The token that specifies the next page of results Amazon MQ should return. To request the first page, leave nextToken empty.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token that specifies the next page of results Amazon MQ should return. To request the first page, leave nextToken empty.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token that specifies the next page of results Amazon MQ should return. To request the first page, leave nextToken empty.</p>
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
    /// Consumes the builder and constructs a [`ListConfigurationsOutput`](crate::operation::list_configurations::ListConfigurationsOutput).
    pub fn build(self) -> crate::operation::list_configurations::ListConfigurationsOutput {
        crate::operation::list_configurations::ListConfigurationsOutput {
            configurations: self.configurations,
            max_results: self.max_results,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
