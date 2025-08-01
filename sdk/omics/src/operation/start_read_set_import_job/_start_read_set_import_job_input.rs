// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartReadSetImportJobInput {
    /// <p>The read set's sequence store ID.</p>
    pub sequence_store_id: ::std::option::Option<::std::string::String>,
    /// <p>A service role for the job.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
    /// <p>To ensure that jobs don't run multiple times, specify a unique token for each job.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>The job's source files.</p>
    pub sources: ::std::option::Option<::std::vec::Vec<crate::types::StartReadSetImportJobSourceItem>>,
}
impl StartReadSetImportJobInput {
    /// <p>The read set's sequence store ID.</p>
    pub fn sequence_store_id(&self) -> ::std::option::Option<&str> {
        self.sequence_store_id.as_deref()
    }
    /// <p>A service role for the job.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
    /// <p>To ensure that jobs don't run multiple times, specify a unique token for each job.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>The job's source files.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.sources.is_none()`.
    pub fn sources(&self) -> &[crate::types::StartReadSetImportJobSourceItem] {
        self.sources.as_deref().unwrap_or_default()
    }
}
impl StartReadSetImportJobInput {
    /// Creates a new builder-style object to manufacture [`StartReadSetImportJobInput`](crate::operation::start_read_set_import_job::StartReadSetImportJobInput).
    pub fn builder() -> crate::operation::start_read_set_import_job::builders::StartReadSetImportJobInputBuilder {
        crate::operation::start_read_set_import_job::builders::StartReadSetImportJobInputBuilder::default()
    }
}

/// A builder for [`StartReadSetImportJobInput`](crate::operation::start_read_set_import_job::StartReadSetImportJobInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartReadSetImportJobInputBuilder {
    pub(crate) sequence_store_id: ::std::option::Option<::std::string::String>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) sources: ::std::option::Option<::std::vec::Vec<crate::types::StartReadSetImportJobSourceItem>>,
}
impl StartReadSetImportJobInputBuilder {
    /// <p>The read set's sequence store ID.</p>
    /// This field is required.
    pub fn sequence_store_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sequence_store_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The read set's sequence store ID.</p>
    pub fn set_sequence_store_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sequence_store_id = input;
        self
    }
    /// <p>The read set's sequence store ID.</p>
    pub fn get_sequence_store_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.sequence_store_id
    }
    /// <p>A service role for the job.</p>
    /// This field is required.
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A service role for the job.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>A service role for the job.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// <p>To ensure that jobs don't run multiple times, specify a unique token for each job.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>To ensure that jobs don't run multiple times, specify a unique token for each job.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>To ensure that jobs don't run multiple times, specify a unique token for each job.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Appends an item to `sources`.
    ///
    /// To override the contents of this collection use [`set_sources`](Self::set_sources).
    ///
    /// <p>The job's source files.</p>
    pub fn sources(mut self, input: crate::types::StartReadSetImportJobSourceItem) -> Self {
        let mut v = self.sources.unwrap_or_default();
        v.push(input);
        self.sources = ::std::option::Option::Some(v);
        self
    }
    /// <p>The job's source files.</p>
    pub fn set_sources(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::StartReadSetImportJobSourceItem>>) -> Self {
        self.sources = input;
        self
    }
    /// <p>The job's source files.</p>
    pub fn get_sources(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::StartReadSetImportJobSourceItem>> {
        &self.sources
    }
    /// Consumes the builder and constructs a [`StartReadSetImportJobInput`](crate::operation::start_read_set_import_job::StartReadSetImportJobInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::start_read_set_import_job::StartReadSetImportJobInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::start_read_set_import_job::StartReadSetImportJobInput {
            sequence_store_id: self.sequence_store_id,
            role_arn: self.role_arn,
            client_token: self.client_token,
            sources: self.sources,
        })
    }
}
