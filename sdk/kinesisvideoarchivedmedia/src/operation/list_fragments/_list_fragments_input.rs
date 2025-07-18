// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListFragmentsInput {
    /// <p>The name of the stream from which to retrieve a fragment list. Specify either this parameter or the <code>StreamARN</code> parameter.</p>
    pub stream_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the stream from which to retrieve a fragment list. Specify either this parameter or the <code>StreamName</code> parameter.</p>
    pub stream_arn: ::std::option::Option<::std::string::String>,
    /// <p>The total number of fragments to return. If the total number of fragments available is more than the value specified in <code>max-results</code>, then a <code>ListFragmentsOutput$NextToken</code> is provided in the output that you can use to resume pagination.</p>
    pub max_results: ::std::option::Option<i64>,
    /// <p>A token to specify where to start paginating. This is the <code>ListFragmentsOutput$NextToken</code> from a previously truncated response.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>Describes the timestamp range and timestamp origin for the range of fragments to return.</p><note>
    /// <p>This is only required when the <code>NextToken</code> isn't passed in the API.</p>
    /// </note>
    pub fragment_selector: ::std::option::Option<crate::types::FragmentSelector>,
}
impl ListFragmentsInput {
    /// <p>The name of the stream from which to retrieve a fragment list. Specify either this parameter or the <code>StreamARN</code> parameter.</p>
    pub fn stream_name(&self) -> ::std::option::Option<&str> {
        self.stream_name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the stream from which to retrieve a fragment list. Specify either this parameter or the <code>StreamName</code> parameter.</p>
    pub fn stream_arn(&self) -> ::std::option::Option<&str> {
        self.stream_arn.as_deref()
    }
    /// <p>The total number of fragments to return. If the total number of fragments available is more than the value specified in <code>max-results</code>, then a <code>ListFragmentsOutput$NextToken</code> is provided in the output that you can use to resume pagination.</p>
    pub fn max_results(&self) -> ::std::option::Option<i64> {
        self.max_results
    }
    /// <p>A token to specify where to start paginating. This is the <code>ListFragmentsOutput$NextToken</code> from a previously truncated response.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>Describes the timestamp range and timestamp origin for the range of fragments to return.</p><note>
    /// <p>This is only required when the <code>NextToken</code> isn't passed in the API.</p>
    /// </note>
    pub fn fragment_selector(&self) -> ::std::option::Option<&crate::types::FragmentSelector> {
        self.fragment_selector.as_ref()
    }
}
impl ListFragmentsInput {
    /// Creates a new builder-style object to manufacture [`ListFragmentsInput`](crate::operation::list_fragments::ListFragmentsInput).
    pub fn builder() -> crate::operation::list_fragments::builders::ListFragmentsInputBuilder {
        crate::operation::list_fragments::builders::ListFragmentsInputBuilder::default()
    }
}

/// A builder for [`ListFragmentsInput`](crate::operation::list_fragments::ListFragmentsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListFragmentsInputBuilder {
    pub(crate) stream_name: ::std::option::Option<::std::string::String>,
    pub(crate) stream_arn: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i64>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) fragment_selector: ::std::option::Option<crate::types::FragmentSelector>,
}
impl ListFragmentsInputBuilder {
    /// <p>The name of the stream from which to retrieve a fragment list. Specify either this parameter or the <code>StreamARN</code> parameter.</p>
    pub fn stream_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stream_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the stream from which to retrieve a fragment list. Specify either this parameter or the <code>StreamARN</code> parameter.</p>
    pub fn set_stream_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stream_name = input;
        self
    }
    /// <p>The name of the stream from which to retrieve a fragment list. Specify either this parameter or the <code>StreamARN</code> parameter.</p>
    pub fn get_stream_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.stream_name
    }
    /// <p>The Amazon Resource Name (ARN) of the stream from which to retrieve a fragment list. Specify either this parameter or the <code>StreamName</code> parameter.</p>
    pub fn stream_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stream_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the stream from which to retrieve a fragment list. Specify either this parameter or the <code>StreamName</code> parameter.</p>
    pub fn set_stream_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stream_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the stream from which to retrieve a fragment list. Specify either this parameter or the <code>StreamName</code> parameter.</p>
    pub fn get_stream_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.stream_arn
    }
    /// <p>The total number of fragments to return. If the total number of fragments available is more than the value specified in <code>max-results</code>, then a <code>ListFragmentsOutput$NextToken</code> is provided in the output that you can use to resume pagination.</p>
    pub fn max_results(mut self, input: i64) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of fragments to return. If the total number of fragments available is more than the value specified in <code>max-results</code>, then a <code>ListFragmentsOutput$NextToken</code> is provided in the output that you can use to resume pagination.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i64>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The total number of fragments to return. If the total number of fragments available is more than the value specified in <code>max-results</code>, then a <code>ListFragmentsOutput$NextToken</code> is provided in the output that you can use to resume pagination.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i64> {
        &self.max_results
    }
    /// <p>A token to specify where to start paginating. This is the <code>ListFragmentsOutput$NextToken</code> from a previously truncated response.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token to specify where to start paginating. This is the <code>ListFragmentsOutput$NextToken</code> from a previously truncated response.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token to specify where to start paginating. This is the <code>ListFragmentsOutput$NextToken</code> from a previously truncated response.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>Describes the timestamp range and timestamp origin for the range of fragments to return.</p><note>
    /// <p>This is only required when the <code>NextToken</code> isn't passed in the API.</p>
    /// </note>
    pub fn fragment_selector(mut self, input: crate::types::FragmentSelector) -> Self {
        self.fragment_selector = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the timestamp range and timestamp origin for the range of fragments to return.</p><note>
    /// <p>This is only required when the <code>NextToken</code> isn't passed in the API.</p>
    /// </note>
    pub fn set_fragment_selector(mut self, input: ::std::option::Option<crate::types::FragmentSelector>) -> Self {
        self.fragment_selector = input;
        self
    }
    /// <p>Describes the timestamp range and timestamp origin for the range of fragments to return.</p><note>
    /// <p>This is only required when the <code>NextToken</code> isn't passed in the API.</p>
    /// </note>
    pub fn get_fragment_selector(&self) -> &::std::option::Option<crate::types::FragmentSelector> {
        &self.fragment_selector
    }
    /// Consumes the builder and constructs a [`ListFragmentsInput`](crate::operation::list_fragments::ListFragmentsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_fragments::ListFragmentsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_fragments::ListFragmentsInput {
            stream_name: self.stream_name,
            stream_arn: self.stream_arn,
            max_results: self.max_results,
            next_token: self.next_token,
            fragment_selector: self.fragment_selector,
        })
    }
}
