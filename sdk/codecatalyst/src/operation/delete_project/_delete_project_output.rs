// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteProjectOutput {
    /// <p>The name of the space.</p>
    pub space_name: ::std::string::String,
    /// <p>The name of the project in the space.</p>
    pub name: ::std::string::String,
    /// <p>The friendly name displayed to users of the project in Amazon CodeCatalyst.</p>
    pub display_name: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeleteProjectOutput {
    /// <p>The name of the space.</p>
    pub fn space_name(&self) -> &str {
        use std::ops::Deref;
        self.space_name.deref()
    }
    /// <p>The name of the project in the space.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The friendly name displayed to users of the project in Amazon CodeCatalyst.</p>
    pub fn display_name(&self) -> ::std::option::Option<&str> {
        self.display_name.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteProjectOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteProjectOutput {
    /// Creates a new builder-style object to manufacture [`DeleteProjectOutput`](crate::operation::delete_project::DeleteProjectOutput).
    pub fn builder() -> crate::operation::delete_project::builders::DeleteProjectOutputBuilder {
        crate::operation::delete_project::builders::DeleteProjectOutputBuilder::default()
    }
}

/// A builder for [`DeleteProjectOutput`](crate::operation::delete_project::DeleteProjectOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteProjectOutputBuilder {
    pub(crate) space_name: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) display_name: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeleteProjectOutputBuilder {
    /// <p>The name of the space.</p>
    /// This field is required.
    pub fn space_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.space_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the space.</p>
    pub fn set_space_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.space_name = input;
        self
    }
    /// <p>The name of the space.</p>
    pub fn get_space_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.space_name
    }
    /// <p>The name of the project in the space.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the project in the space.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the project in the space.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The friendly name displayed to users of the project in Amazon CodeCatalyst.</p>
    pub fn display_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.display_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The friendly name displayed to users of the project in Amazon CodeCatalyst.</p>
    pub fn set_display_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.display_name = input;
        self
    }
    /// <p>The friendly name displayed to users of the project in Amazon CodeCatalyst.</p>
    pub fn get_display_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.display_name
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteProjectOutput`](crate::operation::delete_project::DeleteProjectOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`space_name`](crate::operation::delete_project::builders::DeleteProjectOutputBuilder::space_name)
    /// - [`name`](crate::operation::delete_project::builders::DeleteProjectOutputBuilder::name)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_project::DeleteProjectOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_project::DeleteProjectOutput {
            space_name: self.space_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "space_name",
                    "space_name was not specified but it is required when building DeleteProjectOutput",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building DeleteProjectOutput",
                )
            })?,
            display_name: self.display_name,
            _request_id: self._request_id,
        })
    }
}
