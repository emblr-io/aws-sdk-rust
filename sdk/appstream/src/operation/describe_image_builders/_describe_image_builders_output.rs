// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeImageBuildersOutput {
    /// <p>Information about the image builders.</p>
    pub image_builders: ::std::option::Option<::std::vec::Vec<crate::types::ImageBuilder>>,
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If there are no more pages, this value is null.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeImageBuildersOutput {
    /// <p>Information about the image builders.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.image_builders.is_none()`.
    pub fn image_builders(&self) -> &[crate::types::ImageBuilder] {
        self.image_builders.as_deref().unwrap_or_default()
    }
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If there are no more pages, this value is null.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeImageBuildersOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeImageBuildersOutput {
    /// Creates a new builder-style object to manufacture [`DescribeImageBuildersOutput`](crate::operation::describe_image_builders::DescribeImageBuildersOutput).
    pub fn builder() -> crate::operation::describe_image_builders::builders::DescribeImageBuildersOutputBuilder {
        crate::operation::describe_image_builders::builders::DescribeImageBuildersOutputBuilder::default()
    }
}

/// A builder for [`DescribeImageBuildersOutput`](crate::operation::describe_image_builders::DescribeImageBuildersOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeImageBuildersOutputBuilder {
    pub(crate) image_builders: ::std::option::Option<::std::vec::Vec<crate::types::ImageBuilder>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeImageBuildersOutputBuilder {
    /// Appends an item to `image_builders`.
    ///
    /// To override the contents of this collection use [`set_image_builders`](Self::set_image_builders).
    ///
    /// <p>Information about the image builders.</p>
    pub fn image_builders(mut self, input: crate::types::ImageBuilder) -> Self {
        let mut v = self.image_builders.unwrap_or_default();
        v.push(input);
        self.image_builders = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the image builders.</p>
    pub fn set_image_builders(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ImageBuilder>>) -> Self {
        self.image_builders = input;
        self
    }
    /// <p>Information about the image builders.</p>
    pub fn get_image_builders(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ImageBuilder>> {
        &self.image_builders
    }
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If there are no more pages, this value is null.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If there are no more pages, this value is null.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If there are no more pages, this value is null.</p>
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
    /// Consumes the builder and constructs a [`DescribeImageBuildersOutput`](crate::operation::describe_image_builders::DescribeImageBuildersOutput).
    pub fn build(self) -> crate::operation::describe_image_builders::DescribeImageBuildersOutput {
        crate::operation::describe_image_builders::DescribeImageBuildersOutput {
            image_builders: self.image_builders,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
