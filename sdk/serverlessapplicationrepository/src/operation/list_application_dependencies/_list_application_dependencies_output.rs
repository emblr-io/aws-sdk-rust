// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListApplicationDependenciesOutput {
    /// <p>An array of application summaries nested in the application.</p>
    pub dependencies: ::std::option::Option<::std::vec::Vec<crate::types::ApplicationDependencySummary>>,
    /// <p>The token to request the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListApplicationDependenciesOutput {
    /// <p>An array of application summaries nested in the application.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.dependencies.is_none()`.
    pub fn dependencies(&self) -> &[crate::types::ApplicationDependencySummary] {
        self.dependencies.as_deref().unwrap_or_default()
    }
    /// <p>The token to request the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListApplicationDependenciesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListApplicationDependenciesOutput {
    /// Creates a new builder-style object to manufacture [`ListApplicationDependenciesOutput`](crate::operation::list_application_dependencies::ListApplicationDependenciesOutput).
    pub fn builder() -> crate::operation::list_application_dependencies::builders::ListApplicationDependenciesOutputBuilder {
        crate::operation::list_application_dependencies::builders::ListApplicationDependenciesOutputBuilder::default()
    }
}

/// A builder for [`ListApplicationDependenciesOutput`](crate::operation::list_application_dependencies::ListApplicationDependenciesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListApplicationDependenciesOutputBuilder {
    pub(crate) dependencies: ::std::option::Option<::std::vec::Vec<crate::types::ApplicationDependencySummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListApplicationDependenciesOutputBuilder {
    /// Appends an item to `dependencies`.
    ///
    /// To override the contents of this collection use [`set_dependencies`](Self::set_dependencies).
    ///
    /// <p>An array of application summaries nested in the application.</p>
    pub fn dependencies(mut self, input: crate::types::ApplicationDependencySummary) -> Self {
        let mut v = self.dependencies.unwrap_or_default();
        v.push(input);
        self.dependencies = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of application summaries nested in the application.</p>
    pub fn set_dependencies(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ApplicationDependencySummary>>) -> Self {
        self.dependencies = input;
        self
    }
    /// <p>An array of application summaries nested in the application.</p>
    pub fn get_dependencies(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ApplicationDependencySummary>> {
        &self.dependencies
    }
    /// <p>The token to request the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to request the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to request the next page of results.</p>
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
    /// Consumes the builder and constructs a [`ListApplicationDependenciesOutput`](crate::operation::list_application_dependencies::ListApplicationDependenciesOutput).
    pub fn build(self) -> crate::operation::list_application_dependencies::ListApplicationDependenciesOutput {
        crate::operation::list_application_dependencies::ListApplicationDependenciesOutput {
            dependencies: self.dependencies,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
