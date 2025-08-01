// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StopAddressListImportJobInput {
    /// <p>The identifier of the import job that needs to be stopped.</p>
    pub job_id: ::std::option::Option<::std::string::String>,
}
impl StopAddressListImportJobInput {
    /// <p>The identifier of the import job that needs to be stopped.</p>
    pub fn job_id(&self) -> ::std::option::Option<&str> {
        self.job_id.as_deref()
    }
}
impl StopAddressListImportJobInput {
    /// Creates a new builder-style object to manufacture [`StopAddressListImportJobInput`](crate::operation::stop_address_list_import_job::StopAddressListImportJobInput).
    pub fn builder() -> crate::operation::stop_address_list_import_job::builders::StopAddressListImportJobInputBuilder {
        crate::operation::stop_address_list_import_job::builders::StopAddressListImportJobInputBuilder::default()
    }
}

/// A builder for [`StopAddressListImportJobInput`](crate::operation::stop_address_list_import_job::StopAddressListImportJobInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StopAddressListImportJobInputBuilder {
    pub(crate) job_id: ::std::option::Option<::std::string::String>,
}
impl StopAddressListImportJobInputBuilder {
    /// <p>The identifier of the import job that needs to be stopped.</p>
    /// This field is required.
    pub fn job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the import job that needs to be stopped.</p>
    pub fn set_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_id = input;
        self
    }
    /// <p>The identifier of the import job that needs to be stopped.</p>
    pub fn get_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_id
    }
    /// Consumes the builder and constructs a [`StopAddressListImportJobInput`](crate::operation::stop_address_list_import_job::StopAddressListImportJobInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::stop_address_list_import_job::StopAddressListImportJobInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::stop_address_list_import_job::StopAddressListImportJobInput { job_id: self.job_id })
    }
}
