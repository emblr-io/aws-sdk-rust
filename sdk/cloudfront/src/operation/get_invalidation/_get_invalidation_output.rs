// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The returned result of the corresponding request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetInvalidationOutput {
    /// <p>The invalidation's information. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/InvalidationDatatype.html">Invalidation Complex Type</a>.</p>
    pub invalidation: ::std::option::Option<crate::types::Invalidation>,
    _request_id: Option<String>,
}
impl GetInvalidationOutput {
    /// <p>The invalidation's information. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/InvalidationDatatype.html">Invalidation Complex Type</a>.</p>
    pub fn invalidation(&self) -> ::std::option::Option<&crate::types::Invalidation> {
        self.invalidation.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetInvalidationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetInvalidationOutput {
    /// Creates a new builder-style object to manufacture [`GetInvalidationOutput`](crate::operation::get_invalidation::GetInvalidationOutput).
    pub fn builder() -> crate::operation::get_invalidation::builders::GetInvalidationOutputBuilder {
        crate::operation::get_invalidation::builders::GetInvalidationOutputBuilder::default()
    }
}

/// A builder for [`GetInvalidationOutput`](crate::operation::get_invalidation::GetInvalidationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetInvalidationOutputBuilder {
    pub(crate) invalidation: ::std::option::Option<crate::types::Invalidation>,
    _request_id: Option<String>,
}
impl GetInvalidationOutputBuilder {
    /// <p>The invalidation's information. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/InvalidationDatatype.html">Invalidation Complex Type</a>.</p>
    pub fn invalidation(mut self, input: crate::types::Invalidation) -> Self {
        self.invalidation = ::std::option::Option::Some(input);
        self
    }
    /// <p>The invalidation's information. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/InvalidationDatatype.html">Invalidation Complex Type</a>.</p>
    pub fn set_invalidation(mut self, input: ::std::option::Option<crate::types::Invalidation>) -> Self {
        self.invalidation = input;
        self
    }
    /// <p>The invalidation's information. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/InvalidationDatatype.html">Invalidation Complex Type</a>.</p>
    pub fn get_invalidation(&self) -> &::std::option::Option<crate::types::Invalidation> {
        &self.invalidation
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetInvalidationOutput`](crate::operation::get_invalidation::GetInvalidationOutput).
    pub fn build(self) -> crate::operation::get_invalidation::GetInvalidationOutput {
        crate::operation::get_invalidation::GetInvalidationOutput {
            invalidation: self.invalidation,
            _request_id: self._request_id,
        }
    }
}
