// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>This contains the information about recovery points returned in results of a search job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SearchJobBackupsResult {
    /// <p>This is the status of the search job backup result.</p>
    pub status: ::std::option::Option<crate::types::SearchJobState>,
    /// <p>This is the status message included with the results.</p>
    pub status_message: ::std::option::Option<::std::string::String>,
    /// <p>This is the resource type of the search.</p>
    pub resource_type: ::std::option::Option<crate::types::ResourceType>,
    /// <p>The Amazon Resource Name (ARN) that uniquely identifies the backup resources.</p>
    pub backup_resource_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) that uniquely identifies the source resources.</p>
    pub source_resource_arn: ::std::option::Option<::std::string::String>,
    /// <p>This is the creation time of the backup index.</p>
    pub index_creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>This is the creation time of the backup (recovery point).</p>
    pub backup_creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl SearchJobBackupsResult {
    /// <p>This is the status of the search job backup result.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::SearchJobState> {
        self.status.as_ref()
    }
    /// <p>This is the status message included with the results.</p>
    pub fn status_message(&self) -> ::std::option::Option<&str> {
        self.status_message.as_deref()
    }
    /// <p>This is the resource type of the search.</p>
    pub fn resource_type(&self) -> ::std::option::Option<&crate::types::ResourceType> {
        self.resource_type.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) that uniquely identifies the backup resources.</p>
    pub fn backup_resource_arn(&self) -> ::std::option::Option<&str> {
        self.backup_resource_arn.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) that uniquely identifies the source resources.</p>
    pub fn source_resource_arn(&self) -> ::std::option::Option<&str> {
        self.source_resource_arn.as_deref()
    }
    /// <p>This is the creation time of the backup index.</p>
    pub fn index_creation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.index_creation_time.as_ref()
    }
    /// <p>This is the creation time of the backup (recovery point).</p>
    pub fn backup_creation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.backup_creation_time.as_ref()
    }
}
impl SearchJobBackupsResult {
    /// Creates a new builder-style object to manufacture [`SearchJobBackupsResult`](crate::types::SearchJobBackupsResult).
    pub fn builder() -> crate::types::builders::SearchJobBackupsResultBuilder {
        crate::types::builders::SearchJobBackupsResultBuilder::default()
    }
}

/// A builder for [`SearchJobBackupsResult`](crate::types::SearchJobBackupsResult).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SearchJobBackupsResultBuilder {
    pub(crate) status: ::std::option::Option<crate::types::SearchJobState>,
    pub(crate) status_message: ::std::option::Option<::std::string::String>,
    pub(crate) resource_type: ::std::option::Option<crate::types::ResourceType>,
    pub(crate) backup_resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) source_resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) index_creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) backup_creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl SearchJobBackupsResultBuilder {
    /// <p>This is the status of the search job backup result.</p>
    pub fn status(mut self, input: crate::types::SearchJobState) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>This is the status of the search job backup result.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::SearchJobState>) -> Self {
        self.status = input;
        self
    }
    /// <p>This is the status of the search job backup result.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::SearchJobState> {
        &self.status
    }
    /// <p>This is the status message included with the results.</p>
    pub fn status_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>This is the status message included with the results.</p>
    pub fn set_status_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_message = input;
        self
    }
    /// <p>This is the status message included with the results.</p>
    pub fn get_status_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_message
    }
    /// <p>This is the resource type of the search.</p>
    pub fn resource_type(mut self, input: crate::types::ResourceType) -> Self {
        self.resource_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>This is the resource type of the search.</p>
    pub fn set_resource_type(mut self, input: ::std::option::Option<crate::types::ResourceType>) -> Self {
        self.resource_type = input;
        self
    }
    /// <p>This is the resource type of the search.</p>
    pub fn get_resource_type(&self) -> &::std::option::Option<crate::types::ResourceType> {
        &self.resource_type
    }
    /// <p>The Amazon Resource Name (ARN) that uniquely identifies the backup resources.</p>
    pub fn backup_resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.backup_resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) that uniquely identifies the backup resources.</p>
    pub fn set_backup_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.backup_resource_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) that uniquely identifies the backup resources.</p>
    pub fn get_backup_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.backup_resource_arn
    }
    /// <p>The Amazon Resource Name (ARN) that uniquely identifies the source resources.</p>
    pub fn source_resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) that uniquely identifies the source resources.</p>
    pub fn set_source_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_resource_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) that uniquely identifies the source resources.</p>
    pub fn get_source_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_resource_arn
    }
    /// <p>This is the creation time of the backup index.</p>
    pub fn index_creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.index_creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>This is the creation time of the backup index.</p>
    pub fn set_index_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.index_creation_time = input;
        self
    }
    /// <p>This is the creation time of the backup index.</p>
    pub fn get_index_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.index_creation_time
    }
    /// <p>This is the creation time of the backup (recovery point).</p>
    pub fn backup_creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.backup_creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>This is the creation time of the backup (recovery point).</p>
    pub fn set_backup_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.backup_creation_time = input;
        self
    }
    /// <p>This is the creation time of the backup (recovery point).</p>
    pub fn get_backup_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.backup_creation_time
    }
    /// Consumes the builder and constructs a [`SearchJobBackupsResult`](crate::types::SearchJobBackupsResult).
    pub fn build(self) -> crate::types::SearchJobBackupsResult {
        crate::types::SearchJobBackupsResult {
            status: self.status,
            status_message: self.status_message,
            resource_type: self.resource_type,
            backup_resource_arn: self.backup_resource_arn,
            source_resource_arn: self.source_resource_arn,
            index_creation_time: self.index_creation_time,
            backup_creation_time: self.backup_creation_time,
        }
    }
}
