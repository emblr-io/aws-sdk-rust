// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListMlTransformsOutput {
    /// <p>The identifiers of all the machine learning transforms in the account, or the machine learning transforms with the specified tags.</p>
    pub transform_ids: ::std::vec::Vec<::std::string::String>,
    /// <p>A continuation token, if the returned list does not contain the last metric available.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListMlTransformsOutput {
    /// <p>The identifiers of all the machine learning transforms in the account, or the machine learning transforms with the specified tags.</p>
    pub fn transform_ids(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.transform_ids.deref()
    }
    /// <p>A continuation token, if the returned list does not contain the last metric available.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListMlTransformsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListMlTransformsOutput {
    /// Creates a new builder-style object to manufacture [`ListMlTransformsOutput`](crate::operation::list_ml_transforms::ListMlTransformsOutput).
    pub fn builder() -> crate::operation::list_ml_transforms::builders::ListMlTransformsOutputBuilder {
        crate::operation::list_ml_transforms::builders::ListMlTransformsOutputBuilder::default()
    }
}

/// A builder for [`ListMlTransformsOutput`](crate::operation::list_ml_transforms::ListMlTransformsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListMlTransformsOutputBuilder {
    pub(crate) transform_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListMlTransformsOutputBuilder {
    /// Appends an item to `transform_ids`.
    ///
    /// To override the contents of this collection use [`set_transform_ids`](Self::set_transform_ids).
    ///
    /// <p>The identifiers of all the machine learning transforms in the account, or the machine learning transforms with the specified tags.</p>
    pub fn transform_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.transform_ids.unwrap_or_default();
        v.push(input.into());
        self.transform_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The identifiers of all the machine learning transforms in the account, or the machine learning transforms with the specified tags.</p>
    pub fn set_transform_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.transform_ids = input;
        self
    }
    /// <p>The identifiers of all the machine learning transforms in the account, or the machine learning transforms with the specified tags.</p>
    pub fn get_transform_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.transform_ids
    }
    /// <p>A continuation token, if the returned list does not contain the last metric available.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A continuation token, if the returned list does not contain the last metric available.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A continuation token, if the returned list does not contain the last metric available.</p>
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
    /// Consumes the builder and constructs a [`ListMlTransformsOutput`](crate::operation::list_ml_transforms::ListMlTransformsOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`transform_ids`](crate::operation::list_ml_transforms::builders::ListMlTransformsOutputBuilder::transform_ids)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_ml_transforms::ListMlTransformsOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_ml_transforms::ListMlTransformsOutput {
            transform_ids: self.transform_ids.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "transform_ids",
                    "transform_ids was not specified but it is required when building ListMlTransformsOutput",
                )
            })?,
            next_token: self.next_token,
            _request_id: self._request_id,
        })
    }
}
