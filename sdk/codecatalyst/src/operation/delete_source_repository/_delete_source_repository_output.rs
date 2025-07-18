// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteSourceRepositoryOutput {
    /// <p>The name of the space.</p>
    pub space_name: ::std::string::String,
    /// <p>The name of the project in the space.</p>
    pub project_name: ::std::string::String,
    /// <p>The name of the repository.</p>
    pub name: ::std::string::String,
    _request_id: Option<String>,
}
impl DeleteSourceRepositoryOutput {
    /// <p>The name of the space.</p>
    pub fn space_name(&self) -> &str {
        use std::ops::Deref;
        self.space_name.deref()
    }
    /// <p>The name of the project in the space.</p>
    pub fn project_name(&self) -> &str {
        use std::ops::Deref;
        self.project_name.deref()
    }
    /// <p>The name of the repository.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteSourceRepositoryOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteSourceRepositoryOutput {
    /// Creates a new builder-style object to manufacture [`DeleteSourceRepositoryOutput`](crate::operation::delete_source_repository::DeleteSourceRepositoryOutput).
    pub fn builder() -> crate::operation::delete_source_repository::builders::DeleteSourceRepositoryOutputBuilder {
        crate::operation::delete_source_repository::builders::DeleteSourceRepositoryOutputBuilder::default()
    }
}

/// A builder for [`DeleteSourceRepositoryOutput`](crate::operation::delete_source_repository::DeleteSourceRepositoryOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteSourceRepositoryOutputBuilder {
    pub(crate) space_name: ::std::option::Option<::std::string::String>,
    pub(crate) project_name: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeleteSourceRepositoryOutputBuilder {
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
    pub fn project_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.project_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the project in the space.</p>
    pub fn set_project_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.project_name = input;
        self
    }
    /// <p>The name of the project in the space.</p>
    pub fn get_project_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.project_name
    }
    /// <p>The name of the repository.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the repository.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the repository.</p>
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
    /// Consumes the builder and constructs a [`DeleteSourceRepositoryOutput`](crate::operation::delete_source_repository::DeleteSourceRepositoryOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`space_name`](crate::operation::delete_source_repository::builders::DeleteSourceRepositoryOutputBuilder::space_name)
    /// - [`project_name`](crate::operation::delete_source_repository::builders::DeleteSourceRepositoryOutputBuilder::project_name)
    /// - [`name`](crate::operation::delete_source_repository::builders::DeleteSourceRepositoryOutputBuilder::name)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_source_repository::DeleteSourceRepositoryOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_source_repository::DeleteSourceRepositoryOutput {
            space_name: self.space_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "space_name",
                    "space_name was not specified but it is required when building DeleteSourceRepositoryOutput",
                )
            })?,
            project_name: self.project_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "project_name",
                    "project_name was not specified but it is required when building DeleteSourceRepositoryOutput",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building DeleteSourceRepositoryOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
