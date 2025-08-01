// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListIngestConfigurationsOutput {
    /// <p>List of the matching ingest configurations (summary information only).</p>
    pub ingest_configurations: ::std::vec::Vec<crate::types::IngestConfigurationSummary>,
    /// <p>If there are more IngestConfigurations than <code>maxResults</code>, use <code>nextToken</code> in the request to get the next set.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListIngestConfigurationsOutput {
    /// <p>List of the matching ingest configurations (summary information only).</p>
    pub fn ingest_configurations(&self) -> &[crate::types::IngestConfigurationSummary] {
        use std::ops::Deref;
        self.ingest_configurations.deref()
    }
    /// <p>If there are more IngestConfigurations than <code>maxResults</code>, use <code>nextToken</code> in the request to get the next set.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListIngestConfigurationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListIngestConfigurationsOutput {
    /// Creates a new builder-style object to manufacture [`ListIngestConfigurationsOutput`](crate::operation::list_ingest_configurations::ListIngestConfigurationsOutput).
    pub fn builder() -> crate::operation::list_ingest_configurations::builders::ListIngestConfigurationsOutputBuilder {
        crate::operation::list_ingest_configurations::builders::ListIngestConfigurationsOutputBuilder::default()
    }
}

/// A builder for [`ListIngestConfigurationsOutput`](crate::operation::list_ingest_configurations::ListIngestConfigurationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListIngestConfigurationsOutputBuilder {
    pub(crate) ingest_configurations: ::std::option::Option<::std::vec::Vec<crate::types::IngestConfigurationSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListIngestConfigurationsOutputBuilder {
    /// Appends an item to `ingest_configurations`.
    ///
    /// To override the contents of this collection use [`set_ingest_configurations`](Self::set_ingest_configurations).
    ///
    /// <p>List of the matching ingest configurations (summary information only).</p>
    pub fn ingest_configurations(mut self, input: crate::types::IngestConfigurationSummary) -> Self {
        let mut v = self.ingest_configurations.unwrap_or_default();
        v.push(input);
        self.ingest_configurations = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of the matching ingest configurations (summary information only).</p>
    pub fn set_ingest_configurations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::IngestConfigurationSummary>>) -> Self {
        self.ingest_configurations = input;
        self
    }
    /// <p>List of the matching ingest configurations (summary information only).</p>
    pub fn get_ingest_configurations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::IngestConfigurationSummary>> {
        &self.ingest_configurations
    }
    /// <p>If there are more IngestConfigurations than <code>maxResults</code>, use <code>nextToken</code> in the request to get the next set.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If there are more IngestConfigurations than <code>maxResults</code>, use <code>nextToken</code> in the request to get the next set.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If there are more IngestConfigurations than <code>maxResults</code>, use <code>nextToken</code> in the request to get the next set.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListIngestConfigurationsOutput`](crate::operation::list_ingest_configurations::ListIngestConfigurationsOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`ingest_configurations`](crate::operation::list_ingest_configurations::builders::ListIngestConfigurationsOutputBuilder::ingest_configurations)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_ingest_configurations::ListIngestConfigurationsOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_ingest_configurations::ListIngestConfigurationsOutput {
            ingest_configurations: self.ingest_configurations.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "ingest_configurations",
                    "ingest_configurations was not specified but it is required when building ListIngestConfigurationsOutput",
                )
            })?,
            next_token: self.next_token,
            _request_id: self._request_id,
        })
    }
}
