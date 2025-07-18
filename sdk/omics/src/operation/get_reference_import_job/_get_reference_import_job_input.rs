// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetReferenceImportJobInput {
    /// <p>The job's ID.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The job's reference store ID.</p>
    pub reference_store_id: ::std::option::Option<::std::string::String>,
}
impl GetReferenceImportJobInput {
    /// <p>The job's ID.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The job's reference store ID.</p>
    pub fn reference_store_id(&self) -> ::std::option::Option<&str> {
        self.reference_store_id.as_deref()
    }
}
impl GetReferenceImportJobInput {
    /// Creates a new builder-style object to manufacture [`GetReferenceImportJobInput`](crate::operation::get_reference_import_job::GetReferenceImportJobInput).
    pub fn builder() -> crate::operation::get_reference_import_job::builders::GetReferenceImportJobInputBuilder {
        crate::operation::get_reference_import_job::builders::GetReferenceImportJobInputBuilder::default()
    }
}

/// A builder for [`GetReferenceImportJobInput`](crate::operation::get_reference_import_job::GetReferenceImportJobInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetReferenceImportJobInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) reference_store_id: ::std::option::Option<::std::string::String>,
}
impl GetReferenceImportJobInputBuilder {
    /// <p>The job's ID.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The job's ID.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The job's ID.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The job's reference store ID.</p>
    /// This field is required.
    pub fn reference_store_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.reference_store_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The job's reference store ID.</p>
    pub fn set_reference_store_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.reference_store_id = input;
        self
    }
    /// <p>The job's reference store ID.</p>
    pub fn get_reference_store_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.reference_store_id
    }
    /// Consumes the builder and constructs a [`GetReferenceImportJobInput`](crate::operation::get_reference_import_job::GetReferenceImportJobInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_reference_import_job::GetReferenceImportJobInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_reference_import_job::GetReferenceImportJobInput {
            id: self.id,
            reference_store_id: self.reference_store_id,
        })
    }
}
