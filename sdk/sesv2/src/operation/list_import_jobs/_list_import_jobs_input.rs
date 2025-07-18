// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents a request to list all of the import jobs for a data destination within the specified maximum number of import jobs.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListImportJobsInput {
    /// <p>The destination of the import job, which can be used to list import jobs that have a certain <code>ImportDestinationType</code>.</p>
    pub import_destination_type: ::std::option::Option<crate::types::ImportDestinationType>,
    /// <p>A string token indicating that there might be additional import jobs available to be listed. Copy this token to a subsequent call to <code>ListImportJobs</code> with the same parameters to retrieve the next page of import jobs.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>Maximum number of import jobs to return at once. Use this parameter to paginate results. If additional import jobs exist beyond the specified limit, the <code>NextToken</code> element is sent in the response. Use the <code>NextToken</code> value in subsequent requests to retrieve additional addresses.</p>
    pub page_size: ::std::option::Option<i32>,
}
impl ListImportJobsInput {
    /// <p>The destination of the import job, which can be used to list import jobs that have a certain <code>ImportDestinationType</code>.</p>
    pub fn import_destination_type(&self) -> ::std::option::Option<&crate::types::ImportDestinationType> {
        self.import_destination_type.as_ref()
    }
    /// <p>A string token indicating that there might be additional import jobs available to be listed. Copy this token to a subsequent call to <code>ListImportJobs</code> with the same parameters to retrieve the next page of import jobs.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>Maximum number of import jobs to return at once. Use this parameter to paginate results. If additional import jobs exist beyond the specified limit, the <code>NextToken</code> element is sent in the response. Use the <code>NextToken</code> value in subsequent requests to retrieve additional addresses.</p>
    pub fn page_size(&self) -> ::std::option::Option<i32> {
        self.page_size
    }
}
impl ListImportJobsInput {
    /// Creates a new builder-style object to manufacture [`ListImportJobsInput`](crate::operation::list_import_jobs::ListImportJobsInput).
    pub fn builder() -> crate::operation::list_import_jobs::builders::ListImportJobsInputBuilder {
        crate::operation::list_import_jobs::builders::ListImportJobsInputBuilder::default()
    }
}

/// A builder for [`ListImportJobsInput`](crate::operation::list_import_jobs::ListImportJobsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListImportJobsInputBuilder {
    pub(crate) import_destination_type: ::std::option::Option<crate::types::ImportDestinationType>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) page_size: ::std::option::Option<i32>,
}
impl ListImportJobsInputBuilder {
    /// <p>The destination of the import job, which can be used to list import jobs that have a certain <code>ImportDestinationType</code>.</p>
    pub fn import_destination_type(mut self, input: crate::types::ImportDestinationType) -> Self {
        self.import_destination_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The destination of the import job, which can be used to list import jobs that have a certain <code>ImportDestinationType</code>.</p>
    pub fn set_import_destination_type(mut self, input: ::std::option::Option<crate::types::ImportDestinationType>) -> Self {
        self.import_destination_type = input;
        self
    }
    /// <p>The destination of the import job, which can be used to list import jobs that have a certain <code>ImportDestinationType</code>.</p>
    pub fn get_import_destination_type(&self) -> &::std::option::Option<crate::types::ImportDestinationType> {
        &self.import_destination_type
    }
    /// <p>A string token indicating that there might be additional import jobs available to be listed. Copy this token to a subsequent call to <code>ListImportJobs</code> with the same parameters to retrieve the next page of import jobs.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A string token indicating that there might be additional import jobs available to be listed. Copy this token to a subsequent call to <code>ListImportJobs</code> with the same parameters to retrieve the next page of import jobs.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A string token indicating that there might be additional import jobs available to be listed. Copy this token to a subsequent call to <code>ListImportJobs</code> with the same parameters to retrieve the next page of import jobs.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>Maximum number of import jobs to return at once. Use this parameter to paginate results. If additional import jobs exist beyond the specified limit, the <code>NextToken</code> element is sent in the response. Use the <code>NextToken</code> value in subsequent requests to retrieve additional addresses.</p>
    pub fn page_size(mut self, input: i32) -> Self {
        self.page_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>Maximum number of import jobs to return at once. Use this parameter to paginate results. If additional import jobs exist beyond the specified limit, the <code>NextToken</code> element is sent in the response. Use the <code>NextToken</code> value in subsequent requests to retrieve additional addresses.</p>
    pub fn set_page_size(mut self, input: ::std::option::Option<i32>) -> Self {
        self.page_size = input;
        self
    }
    /// <p>Maximum number of import jobs to return at once. Use this parameter to paginate results. If additional import jobs exist beyond the specified limit, the <code>NextToken</code> element is sent in the response. Use the <code>NextToken</code> value in subsequent requests to retrieve additional addresses.</p>
    pub fn get_page_size(&self) -> &::std::option::Option<i32> {
        &self.page_size
    }
    /// Consumes the builder and constructs a [`ListImportJobsInput`](crate::operation::list_import_jobs::ListImportJobsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_import_jobs::ListImportJobsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_import_jobs::ListImportJobsInput {
            import_destination_type: self.import_destination_type,
            next_token: self.next_token,
            page_size: self.page_size,
        })
    }
}
