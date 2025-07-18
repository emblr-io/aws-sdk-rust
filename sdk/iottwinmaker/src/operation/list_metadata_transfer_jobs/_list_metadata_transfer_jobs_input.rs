// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListMetadataTransferJobsInput {
    /// <p>The metadata transfer job's source type.</p>
    pub source_type: ::std::option::Option<crate::types::SourceType>,
    /// <p>The metadata transfer job's destination type.</p>
    pub destination_type: ::std::option::Option<crate::types::DestinationType>,
    /// <p>An object that filters metadata transfer jobs.</p>
    pub filters: ::std::option::Option<::std::vec::Vec<crate::types::ListMetadataTransferJobsFilter>>,
    /// <p>The string that specifies the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return at one time.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListMetadataTransferJobsInput {
    /// <p>The metadata transfer job's source type.</p>
    pub fn source_type(&self) -> ::std::option::Option<&crate::types::SourceType> {
        self.source_type.as_ref()
    }
    /// <p>The metadata transfer job's destination type.</p>
    pub fn destination_type(&self) -> ::std::option::Option<&crate::types::DestinationType> {
        self.destination_type.as_ref()
    }
    /// <p>An object that filters metadata transfer jobs.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters.is_none()`.
    pub fn filters(&self) -> &[crate::types::ListMetadataTransferJobsFilter] {
        self.filters.as_deref().unwrap_or_default()
    }
    /// <p>The string that specifies the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to return at one time.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListMetadataTransferJobsInput {
    /// Creates a new builder-style object to manufacture [`ListMetadataTransferJobsInput`](crate::operation::list_metadata_transfer_jobs::ListMetadataTransferJobsInput).
    pub fn builder() -> crate::operation::list_metadata_transfer_jobs::builders::ListMetadataTransferJobsInputBuilder {
        crate::operation::list_metadata_transfer_jobs::builders::ListMetadataTransferJobsInputBuilder::default()
    }
}

/// A builder for [`ListMetadataTransferJobsInput`](crate::operation::list_metadata_transfer_jobs::ListMetadataTransferJobsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListMetadataTransferJobsInputBuilder {
    pub(crate) source_type: ::std::option::Option<crate::types::SourceType>,
    pub(crate) destination_type: ::std::option::Option<crate::types::DestinationType>,
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::ListMetadataTransferJobsFilter>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListMetadataTransferJobsInputBuilder {
    /// <p>The metadata transfer job's source type.</p>
    /// This field is required.
    pub fn source_type(mut self, input: crate::types::SourceType) -> Self {
        self.source_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The metadata transfer job's source type.</p>
    pub fn set_source_type(mut self, input: ::std::option::Option<crate::types::SourceType>) -> Self {
        self.source_type = input;
        self
    }
    /// <p>The metadata transfer job's source type.</p>
    pub fn get_source_type(&self) -> &::std::option::Option<crate::types::SourceType> {
        &self.source_type
    }
    /// <p>The metadata transfer job's destination type.</p>
    /// This field is required.
    pub fn destination_type(mut self, input: crate::types::DestinationType) -> Self {
        self.destination_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The metadata transfer job's destination type.</p>
    pub fn set_destination_type(mut self, input: ::std::option::Option<crate::types::DestinationType>) -> Self {
        self.destination_type = input;
        self
    }
    /// <p>The metadata transfer job's destination type.</p>
    pub fn get_destination_type(&self) -> &::std::option::Option<crate::types::DestinationType> {
        &self.destination_type
    }
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>An object that filters metadata transfer jobs.</p>
    pub fn filters(mut self, input: crate::types::ListMetadataTransferJobsFilter) -> Self {
        let mut v = self.filters.unwrap_or_default();
        v.push(input);
        self.filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>An object that filters metadata transfer jobs.</p>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ListMetadataTransferJobsFilter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>An object that filters metadata transfer jobs.</p>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ListMetadataTransferJobsFilter>> {
        &self.filters
    }
    /// <p>The string that specifies the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The string that specifies the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The string that specifies the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results to return at one time.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return at one time.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return at one time.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListMetadataTransferJobsInput`](crate::operation::list_metadata_transfer_jobs::ListMetadataTransferJobsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_metadata_transfer_jobs::ListMetadataTransferJobsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_metadata_transfer_jobs::ListMetadataTransferJobsInput {
            source_type: self.source_type,
            destination_type: self.destination_type,
            filters: self.filters,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
