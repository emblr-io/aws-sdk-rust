// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateMetadataTransferJobInput {
    /// <p>The metadata transfer job Id.</p>
    pub metadata_transfer_job_id: ::std::option::Option<::std::string::String>,
    /// <p>The metadata transfer job description.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The metadata transfer job sources.</p>
    pub sources: ::std::option::Option<::std::vec::Vec<crate::types::SourceConfiguration>>,
    /// <p>The metadata transfer job destination.</p>
    pub destination: ::std::option::Option<crate::types::DestinationConfiguration>,
}
impl CreateMetadataTransferJobInput {
    /// <p>The metadata transfer job Id.</p>
    pub fn metadata_transfer_job_id(&self) -> ::std::option::Option<&str> {
        self.metadata_transfer_job_id.as_deref()
    }
    /// <p>The metadata transfer job description.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The metadata transfer job sources.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.sources.is_none()`.
    pub fn sources(&self) -> &[crate::types::SourceConfiguration] {
        self.sources.as_deref().unwrap_or_default()
    }
    /// <p>The metadata transfer job destination.</p>
    pub fn destination(&self) -> ::std::option::Option<&crate::types::DestinationConfiguration> {
        self.destination.as_ref()
    }
}
impl CreateMetadataTransferJobInput {
    /// Creates a new builder-style object to manufacture [`CreateMetadataTransferJobInput`](crate::operation::create_metadata_transfer_job::CreateMetadataTransferJobInput).
    pub fn builder() -> crate::operation::create_metadata_transfer_job::builders::CreateMetadataTransferJobInputBuilder {
        crate::operation::create_metadata_transfer_job::builders::CreateMetadataTransferJobInputBuilder::default()
    }
}

/// A builder for [`CreateMetadataTransferJobInput`](crate::operation::create_metadata_transfer_job::CreateMetadataTransferJobInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateMetadataTransferJobInputBuilder {
    pub(crate) metadata_transfer_job_id: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) sources: ::std::option::Option<::std::vec::Vec<crate::types::SourceConfiguration>>,
    pub(crate) destination: ::std::option::Option<crate::types::DestinationConfiguration>,
}
impl CreateMetadataTransferJobInputBuilder {
    /// <p>The metadata transfer job Id.</p>
    pub fn metadata_transfer_job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.metadata_transfer_job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The metadata transfer job Id.</p>
    pub fn set_metadata_transfer_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.metadata_transfer_job_id = input;
        self
    }
    /// <p>The metadata transfer job Id.</p>
    pub fn get_metadata_transfer_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.metadata_transfer_job_id
    }
    /// <p>The metadata transfer job description.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The metadata transfer job description.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The metadata transfer job description.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `sources`.
    ///
    /// To override the contents of this collection use [`set_sources`](Self::set_sources).
    ///
    /// <p>The metadata transfer job sources.</p>
    pub fn sources(mut self, input: crate::types::SourceConfiguration) -> Self {
        let mut v = self.sources.unwrap_or_default();
        v.push(input);
        self.sources = ::std::option::Option::Some(v);
        self
    }
    /// <p>The metadata transfer job sources.</p>
    pub fn set_sources(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SourceConfiguration>>) -> Self {
        self.sources = input;
        self
    }
    /// <p>The metadata transfer job sources.</p>
    pub fn get_sources(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SourceConfiguration>> {
        &self.sources
    }
    /// <p>The metadata transfer job destination.</p>
    /// This field is required.
    pub fn destination(mut self, input: crate::types::DestinationConfiguration) -> Self {
        self.destination = ::std::option::Option::Some(input);
        self
    }
    /// <p>The metadata transfer job destination.</p>
    pub fn set_destination(mut self, input: ::std::option::Option<crate::types::DestinationConfiguration>) -> Self {
        self.destination = input;
        self
    }
    /// <p>The metadata transfer job destination.</p>
    pub fn get_destination(&self) -> &::std::option::Option<crate::types::DestinationConfiguration> {
        &self.destination
    }
    /// Consumes the builder and constructs a [`CreateMetadataTransferJobInput`](crate::operation::create_metadata_transfer_job::CreateMetadataTransferJobInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_metadata_transfer_job::CreateMetadataTransferJobInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_metadata_transfer_job::CreateMetadataTransferJobInput {
            metadata_transfer_job_id: self.metadata_transfer_job_id,
            description: self.description,
            sources: self.sources,
            destination: self.destination,
        })
    }
}
