// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Result message containing a description of the requested environment info.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RetrieveEnvironmentInfoOutput {
    /// <p>The <code>EnvironmentInfoDescription</code> of the environment.</p>
    pub environment_info: ::std::option::Option<::std::vec::Vec<crate::types::EnvironmentInfoDescription>>,
    _request_id: Option<String>,
}
impl RetrieveEnvironmentInfoOutput {
    /// <p>The <code>EnvironmentInfoDescription</code> of the environment.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.environment_info.is_none()`.
    pub fn environment_info(&self) -> &[crate::types::EnvironmentInfoDescription] {
        self.environment_info.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for RetrieveEnvironmentInfoOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl RetrieveEnvironmentInfoOutput {
    /// Creates a new builder-style object to manufacture [`RetrieveEnvironmentInfoOutput`](crate::operation::retrieve_environment_info::RetrieveEnvironmentInfoOutput).
    pub fn builder() -> crate::operation::retrieve_environment_info::builders::RetrieveEnvironmentInfoOutputBuilder {
        crate::operation::retrieve_environment_info::builders::RetrieveEnvironmentInfoOutputBuilder::default()
    }
}

/// A builder for [`RetrieveEnvironmentInfoOutput`](crate::operation::retrieve_environment_info::RetrieveEnvironmentInfoOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RetrieveEnvironmentInfoOutputBuilder {
    pub(crate) environment_info: ::std::option::Option<::std::vec::Vec<crate::types::EnvironmentInfoDescription>>,
    _request_id: Option<String>,
}
impl RetrieveEnvironmentInfoOutputBuilder {
    /// Appends an item to `environment_info`.
    ///
    /// To override the contents of this collection use [`set_environment_info`](Self::set_environment_info).
    ///
    /// <p>The <code>EnvironmentInfoDescription</code> of the environment.</p>
    pub fn environment_info(mut self, input: crate::types::EnvironmentInfoDescription) -> Self {
        let mut v = self.environment_info.unwrap_or_default();
        v.push(input);
        self.environment_info = ::std::option::Option::Some(v);
        self
    }
    /// <p>The <code>EnvironmentInfoDescription</code> of the environment.</p>
    pub fn set_environment_info(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::EnvironmentInfoDescription>>) -> Self {
        self.environment_info = input;
        self
    }
    /// <p>The <code>EnvironmentInfoDescription</code> of the environment.</p>
    pub fn get_environment_info(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EnvironmentInfoDescription>> {
        &self.environment_info
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`RetrieveEnvironmentInfoOutput`](crate::operation::retrieve_environment_info::RetrieveEnvironmentInfoOutput).
    pub fn build(self) -> crate::operation::retrieve_environment_info::RetrieveEnvironmentInfoOutput {
        crate::operation::retrieve_environment_info::RetrieveEnvironmentInfoOutput {
            environment_info: self.environment_info,
            _request_id: self._request_id,
        }
    }
}
