// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The result of a DescribeTrust request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeTrustsOutput {
    /// <p>The list of Trust objects that were retrieved.</p>
    /// <p>It is possible that this list contains less than the number of items specified in the <i>Limit</i> member of the request. This occurs if there are less than the requested number of items left to retrieve, or if the limitations of the operation have been exceeded.</p>
    pub trusts: ::std::option::Option<::std::vec::Vec<crate::types::Trust>>,
    /// <p>If not null, more results are available. Pass this value for the <i>NextToken</i> parameter in a subsequent call to <code>DescribeTrusts</code> to retrieve the next set of items.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeTrustsOutput {
    /// <p>The list of Trust objects that were retrieved.</p>
    /// <p>It is possible that this list contains less than the number of items specified in the <i>Limit</i> member of the request. This occurs if there are less than the requested number of items left to retrieve, or if the limitations of the operation have been exceeded.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.trusts.is_none()`.
    pub fn trusts(&self) -> &[crate::types::Trust] {
        self.trusts.as_deref().unwrap_or_default()
    }
    /// <p>If not null, more results are available. Pass this value for the <i>NextToken</i> parameter in a subsequent call to <code>DescribeTrusts</code> to retrieve the next set of items.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeTrustsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeTrustsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeTrustsOutput`](crate::operation::describe_trusts::DescribeTrustsOutput).
    pub fn builder() -> crate::operation::describe_trusts::builders::DescribeTrustsOutputBuilder {
        crate::operation::describe_trusts::builders::DescribeTrustsOutputBuilder::default()
    }
}

/// A builder for [`DescribeTrustsOutput`](crate::operation::describe_trusts::DescribeTrustsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeTrustsOutputBuilder {
    pub(crate) trusts: ::std::option::Option<::std::vec::Vec<crate::types::Trust>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeTrustsOutputBuilder {
    /// Appends an item to `trusts`.
    ///
    /// To override the contents of this collection use [`set_trusts`](Self::set_trusts).
    ///
    /// <p>The list of Trust objects that were retrieved.</p>
    /// <p>It is possible that this list contains less than the number of items specified in the <i>Limit</i> member of the request. This occurs if there are less than the requested number of items left to retrieve, or if the limitations of the operation have been exceeded.</p>
    pub fn trusts(mut self, input: crate::types::Trust) -> Self {
        let mut v = self.trusts.unwrap_or_default();
        v.push(input);
        self.trusts = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of Trust objects that were retrieved.</p>
    /// <p>It is possible that this list contains less than the number of items specified in the <i>Limit</i> member of the request. This occurs if there are less than the requested number of items left to retrieve, or if the limitations of the operation have been exceeded.</p>
    pub fn set_trusts(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Trust>>) -> Self {
        self.trusts = input;
        self
    }
    /// <p>The list of Trust objects that were retrieved.</p>
    /// <p>It is possible that this list contains less than the number of items specified in the <i>Limit</i> member of the request. This occurs if there are less than the requested number of items left to retrieve, or if the limitations of the operation have been exceeded.</p>
    pub fn get_trusts(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Trust>> {
        &self.trusts
    }
    /// <p>If not null, more results are available. Pass this value for the <i>NextToken</i> parameter in a subsequent call to <code>DescribeTrusts</code> to retrieve the next set of items.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If not null, more results are available. Pass this value for the <i>NextToken</i> parameter in a subsequent call to <code>DescribeTrusts</code> to retrieve the next set of items.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If not null, more results are available. Pass this value for the <i>NextToken</i> parameter in a subsequent call to <code>DescribeTrusts</code> to retrieve the next set of items.</p>
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
    /// Consumes the builder and constructs a [`DescribeTrustsOutput`](crate::operation::describe_trusts::DescribeTrustsOutput).
    pub fn build(self) -> crate::operation::describe_trusts::DescribeTrustsOutput {
        crate::operation::describe_trusts::DescribeTrustsOutput {
            trusts: self.trusts,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
