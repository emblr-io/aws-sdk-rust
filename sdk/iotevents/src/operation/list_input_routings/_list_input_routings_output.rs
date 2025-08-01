// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListInputRoutingsOutput {
    /// <p>Summary information about the routed resources.</p>
    pub routed_resources: ::std::option::Option<::std::vec::Vec<crate::types::RoutedResource>>,
    /// <p>The token that you can use to return the next set of results, or <code>null</code> if there are no more results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListInputRoutingsOutput {
    /// <p>Summary information about the routed resources.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.routed_resources.is_none()`.
    pub fn routed_resources(&self) -> &[crate::types::RoutedResource] {
        self.routed_resources.as_deref().unwrap_or_default()
    }
    /// <p>The token that you can use to return the next set of results, or <code>null</code> if there are no more results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListInputRoutingsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListInputRoutingsOutput {
    /// Creates a new builder-style object to manufacture [`ListInputRoutingsOutput`](crate::operation::list_input_routings::ListInputRoutingsOutput).
    pub fn builder() -> crate::operation::list_input_routings::builders::ListInputRoutingsOutputBuilder {
        crate::operation::list_input_routings::builders::ListInputRoutingsOutputBuilder::default()
    }
}

/// A builder for [`ListInputRoutingsOutput`](crate::operation::list_input_routings::ListInputRoutingsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListInputRoutingsOutputBuilder {
    pub(crate) routed_resources: ::std::option::Option<::std::vec::Vec<crate::types::RoutedResource>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListInputRoutingsOutputBuilder {
    /// Appends an item to `routed_resources`.
    ///
    /// To override the contents of this collection use [`set_routed_resources`](Self::set_routed_resources).
    ///
    /// <p>Summary information about the routed resources.</p>
    pub fn routed_resources(mut self, input: crate::types::RoutedResource) -> Self {
        let mut v = self.routed_resources.unwrap_or_default();
        v.push(input);
        self.routed_resources = ::std::option::Option::Some(v);
        self
    }
    /// <p>Summary information about the routed resources.</p>
    pub fn set_routed_resources(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RoutedResource>>) -> Self {
        self.routed_resources = input;
        self
    }
    /// <p>Summary information about the routed resources.</p>
    pub fn get_routed_resources(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RoutedResource>> {
        &self.routed_resources
    }
    /// <p>The token that you can use to return the next set of results, or <code>null</code> if there are no more results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token that you can use to return the next set of results, or <code>null</code> if there are no more results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token that you can use to return the next set of results, or <code>null</code> if there are no more results.</p>
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
    /// Consumes the builder and constructs a [`ListInputRoutingsOutput`](crate::operation::list_input_routings::ListInputRoutingsOutput).
    pub fn build(self) -> crate::operation::list_input_routings::ListInputRoutingsOutput {
        crate::operation::list_input_routings::ListInputRoutingsOutput {
            routed_resources: self.routed_resources,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
