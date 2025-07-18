// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateProjectOutput {
    /// <p>The date and time that the project was last modified.</p>
    pub last_modified_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The name of the project that you updated.</p>
    pub name: ::std::string::String,
    _request_id: Option<String>,
}
impl UpdateProjectOutput {
    /// <p>The date and time that the project was last modified.</p>
    pub fn last_modified_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_modified_date.as_ref()
    }
    /// <p>The name of the project that you updated.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateProjectOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateProjectOutput {
    /// Creates a new builder-style object to manufacture [`UpdateProjectOutput`](crate::operation::update_project::UpdateProjectOutput).
    pub fn builder() -> crate::operation::update_project::builders::UpdateProjectOutputBuilder {
        crate::operation::update_project::builders::UpdateProjectOutputBuilder::default()
    }
}

/// A builder for [`UpdateProjectOutput`](crate::operation::update_project::UpdateProjectOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateProjectOutputBuilder {
    pub(crate) last_modified_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl UpdateProjectOutputBuilder {
    /// <p>The date and time that the project was last modified.</p>
    pub fn last_modified_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the project was last modified.</p>
    pub fn set_last_modified_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified_date = input;
        self
    }
    /// <p>The date and time that the project was last modified.</p>
    pub fn get_last_modified_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified_date
    }
    /// <p>The name of the project that you updated.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the project that you updated.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the project that you updated.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateProjectOutput`](crate::operation::update_project::UpdateProjectOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::operation::update_project::builders::UpdateProjectOutputBuilder::name)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_project::UpdateProjectOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_project::UpdateProjectOutput {
            last_modified_date: self.last_modified_date,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building UpdateProjectOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
