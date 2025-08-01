// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeConformancePackStatusOutput {
    /// <p>A list of <code>ConformancePackStatusDetail</code> objects.</p>
    pub conformance_pack_status_details: ::std::option::Option<::std::vec::Vec<crate::types::ConformancePackStatusDetail>>,
    /// <p>The <code>nextToken</code> string returned in a previous request that you use to request the next page of results in a paginated response.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeConformancePackStatusOutput {
    /// <p>A list of <code>ConformancePackStatusDetail</code> objects.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.conformance_pack_status_details.is_none()`.
    pub fn conformance_pack_status_details(&self) -> &[crate::types::ConformancePackStatusDetail] {
        self.conformance_pack_status_details.as_deref().unwrap_or_default()
    }
    /// <p>The <code>nextToken</code> string returned in a previous request that you use to request the next page of results in a paginated response.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeConformancePackStatusOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeConformancePackStatusOutput {
    /// Creates a new builder-style object to manufacture [`DescribeConformancePackStatusOutput`](crate::operation::describe_conformance_pack_status::DescribeConformancePackStatusOutput).
    pub fn builder() -> crate::operation::describe_conformance_pack_status::builders::DescribeConformancePackStatusOutputBuilder {
        crate::operation::describe_conformance_pack_status::builders::DescribeConformancePackStatusOutputBuilder::default()
    }
}

/// A builder for [`DescribeConformancePackStatusOutput`](crate::operation::describe_conformance_pack_status::DescribeConformancePackStatusOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeConformancePackStatusOutputBuilder {
    pub(crate) conformance_pack_status_details: ::std::option::Option<::std::vec::Vec<crate::types::ConformancePackStatusDetail>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeConformancePackStatusOutputBuilder {
    /// Appends an item to `conformance_pack_status_details`.
    ///
    /// To override the contents of this collection use [`set_conformance_pack_status_details`](Self::set_conformance_pack_status_details).
    ///
    /// <p>A list of <code>ConformancePackStatusDetail</code> objects.</p>
    pub fn conformance_pack_status_details(mut self, input: crate::types::ConformancePackStatusDetail) -> Self {
        let mut v = self.conformance_pack_status_details.unwrap_or_default();
        v.push(input);
        self.conformance_pack_status_details = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of <code>ConformancePackStatusDetail</code> objects.</p>
    pub fn set_conformance_pack_status_details(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::ConformancePackStatusDetail>>,
    ) -> Self {
        self.conformance_pack_status_details = input;
        self
    }
    /// <p>A list of <code>ConformancePackStatusDetail</code> objects.</p>
    pub fn get_conformance_pack_status_details(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ConformancePackStatusDetail>> {
        &self.conformance_pack_status_details
    }
    /// <p>The <code>nextToken</code> string returned in a previous request that you use to request the next page of results in a paginated response.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>nextToken</code> string returned in a previous request that you use to request the next page of results in a paginated response.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The <code>nextToken</code> string returned in a previous request that you use to request the next page of results in a paginated response.</p>
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
    /// Consumes the builder and constructs a [`DescribeConformancePackStatusOutput`](crate::operation::describe_conformance_pack_status::DescribeConformancePackStatusOutput).
    pub fn build(self) -> crate::operation::describe_conformance_pack_status::DescribeConformancePackStatusOutput {
        crate::operation::describe_conformance_pack_status::DescribeConformancePackStatusOutput {
            conformance_pack_status_details: self.conformance_pack_status_details,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
