// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListMobileSdkReleasesOutput {
    /// <p>The high level information for the available SDK releases. If you specified a <code>Limit</code> in your request, this might not be the full list.</p>
    pub release_summaries: ::std::option::Option<::std::vec::Vec<crate::types::ReleaseSummary>>,
    /// <p>When you request a list of objects with a <code>Limit</code> setting, if the number of objects that are still available for retrieval exceeds the limit, WAF returns a <code>NextMarker</code> value in the response. To retrieve the next batch of objects, provide the marker from the prior call in your next request.</p>
    pub next_marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListMobileSdkReleasesOutput {
    /// <p>The high level information for the available SDK releases. If you specified a <code>Limit</code> in your request, this might not be the full list.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.release_summaries.is_none()`.
    pub fn release_summaries(&self) -> &[crate::types::ReleaseSummary] {
        self.release_summaries.as_deref().unwrap_or_default()
    }
    /// <p>When you request a list of objects with a <code>Limit</code> setting, if the number of objects that are still available for retrieval exceeds the limit, WAF returns a <code>NextMarker</code> value in the response. To retrieve the next batch of objects, provide the marker from the prior call in your next request.</p>
    pub fn next_marker(&self) -> ::std::option::Option<&str> {
        self.next_marker.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListMobileSdkReleasesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListMobileSdkReleasesOutput {
    /// Creates a new builder-style object to manufacture [`ListMobileSdkReleasesOutput`](crate::operation::list_mobile_sdk_releases::ListMobileSdkReleasesOutput).
    pub fn builder() -> crate::operation::list_mobile_sdk_releases::builders::ListMobileSdkReleasesOutputBuilder {
        crate::operation::list_mobile_sdk_releases::builders::ListMobileSdkReleasesOutputBuilder::default()
    }
}

/// A builder for [`ListMobileSdkReleasesOutput`](crate::operation::list_mobile_sdk_releases::ListMobileSdkReleasesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListMobileSdkReleasesOutputBuilder {
    pub(crate) release_summaries: ::std::option::Option<::std::vec::Vec<crate::types::ReleaseSummary>>,
    pub(crate) next_marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListMobileSdkReleasesOutputBuilder {
    /// Appends an item to `release_summaries`.
    ///
    /// To override the contents of this collection use [`set_release_summaries`](Self::set_release_summaries).
    ///
    /// <p>The high level information for the available SDK releases. If you specified a <code>Limit</code> in your request, this might not be the full list.</p>
    pub fn release_summaries(mut self, input: crate::types::ReleaseSummary) -> Self {
        let mut v = self.release_summaries.unwrap_or_default();
        v.push(input);
        self.release_summaries = ::std::option::Option::Some(v);
        self
    }
    /// <p>The high level information for the available SDK releases. If you specified a <code>Limit</code> in your request, this might not be the full list.</p>
    pub fn set_release_summaries(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ReleaseSummary>>) -> Self {
        self.release_summaries = input;
        self
    }
    /// <p>The high level information for the available SDK releases. If you specified a <code>Limit</code> in your request, this might not be the full list.</p>
    pub fn get_release_summaries(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ReleaseSummary>> {
        &self.release_summaries
    }
    /// <p>When you request a list of objects with a <code>Limit</code> setting, if the number of objects that are still available for retrieval exceeds the limit, WAF returns a <code>NextMarker</code> value in the response. To retrieve the next batch of objects, provide the marker from the prior call in your next request.</p>
    pub fn next_marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>When you request a list of objects with a <code>Limit</code> setting, if the number of objects that are still available for retrieval exceeds the limit, WAF returns a <code>NextMarker</code> value in the response. To retrieve the next batch of objects, provide the marker from the prior call in your next request.</p>
    pub fn set_next_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_marker = input;
        self
    }
    /// <p>When you request a list of objects with a <code>Limit</code> setting, if the number of objects that are still available for retrieval exceeds the limit, WAF returns a <code>NextMarker</code> value in the response. To retrieve the next batch of objects, provide the marker from the prior call in your next request.</p>
    pub fn get_next_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_marker
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListMobileSdkReleasesOutput`](crate::operation::list_mobile_sdk_releases::ListMobileSdkReleasesOutput).
    pub fn build(self) -> crate::operation::list_mobile_sdk_releases::ListMobileSdkReleasesOutput {
        crate::operation::list_mobile_sdk_releases::ListMobileSdkReleasesOutput {
            release_summaries: self.release_summaries,
            next_marker: self.next_marker,
            _request_id: self._request_id,
        }
    }
}
