// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DetectTextInput {
    /// <p>The input image as base64-encoded bytes or an Amazon S3 object. If you use the AWS CLI to call Amazon Rekognition operations, you can't pass image bytes.</p>
    /// <p>If you are using an AWS SDK to call Amazon Rekognition, you might not need to base64-encode image bytes passed using the <code>Bytes</code> field. For more information, see Images in the Amazon Rekognition developer guide.</p>
    pub image: ::std::option::Option<crate::types::Image>,
    /// <p>Optional parameters that let you set the criteria that the text must meet to be included in your response.</p>
    pub filters: ::std::option::Option<crate::types::DetectTextFilters>,
}
impl DetectTextInput {
    /// <p>The input image as base64-encoded bytes or an Amazon S3 object. If you use the AWS CLI to call Amazon Rekognition operations, you can't pass image bytes.</p>
    /// <p>If you are using an AWS SDK to call Amazon Rekognition, you might not need to base64-encode image bytes passed using the <code>Bytes</code> field. For more information, see Images in the Amazon Rekognition developer guide.</p>
    pub fn image(&self) -> ::std::option::Option<&crate::types::Image> {
        self.image.as_ref()
    }
    /// <p>Optional parameters that let you set the criteria that the text must meet to be included in your response.</p>
    pub fn filters(&self) -> ::std::option::Option<&crate::types::DetectTextFilters> {
        self.filters.as_ref()
    }
}
impl DetectTextInput {
    /// Creates a new builder-style object to manufacture [`DetectTextInput`](crate::operation::detect_text::DetectTextInput).
    pub fn builder() -> crate::operation::detect_text::builders::DetectTextInputBuilder {
        crate::operation::detect_text::builders::DetectTextInputBuilder::default()
    }
}

/// A builder for [`DetectTextInput`](crate::operation::detect_text::DetectTextInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DetectTextInputBuilder {
    pub(crate) image: ::std::option::Option<crate::types::Image>,
    pub(crate) filters: ::std::option::Option<crate::types::DetectTextFilters>,
}
impl DetectTextInputBuilder {
    /// <p>The input image as base64-encoded bytes or an Amazon S3 object. If you use the AWS CLI to call Amazon Rekognition operations, you can't pass image bytes.</p>
    /// <p>If you are using an AWS SDK to call Amazon Rekognition, you might not need to base64-encode image bytes passed using the <code>Bytes</code> field. For more information, see Images in the Amazon Rekognition developer guide.</p>
    /// This field is required.
    pub fn image(mut self, input: crate::types::Image) -> Self {
        self.image = ::std::option::Option::Some(input);
        self
    }
    /// <p>The input image as base64-encoded bytes or an Amazon S3 object. If you use the AWS CLI to call Amazon Rekognition operations, you can't pass image bytes.</p>
    /// <p>If you are using an AWS SDK to call Amazon Rekognition, you might not need to base64-encode image bytes passed using the <code>Bytes</code> field. For more information, see Images in the Amazon Rekognition developer guide.</p>
    pub fn set_image(mut self, input: ::std::option::Option<crate::types::Image>) -> Self {
        self.image = input;
        self
    }
    /// <p>The input image as base64-encoded bytes or an Amazon S3 object. If you use the AWS CLI to call Amazon Rekognition operations, you can't pass image bytes.</p>
    /// <p>If you are using an AWS SDK to call Amazon Rekognition, you might not need to base64-encode image bytes passed using the <code>Bytes</code> field. For more information, see Images in the Amazon Rekognition developer guide.</p>
    pub fn get_image(&self) -> &::std::option::Option<crate::types::Image> {
        &self.image
    }
    /// <p>Optional parameters that let you set the criteria that the text must meet to be included in your response.</p>
    pub fn filters(mut self, input: crate::types::DetectTextFilters) -> Self {
        self.filters = ::std::option::Option::Some(input);
        self
    }
    /// <p>Optional parameters that let you set the criteria that the text must meet to be included in your response.</p>
    pub fn set_filters(mut self, input: ::std::option::Option<crate::types::DetectTextFilters>) -> Self {
        self.filters = input;
        self
    }
    /// <p>Optional parameters that let you set the criteria that the text must meet to be included in your response.</p>
    pub fn get_filters(&self) -> &::std::option::Option<crate::types::DetectTextFilters> {
        &self.filters
    }
    /// Consumes the builder and constructs a [`DetectTextInput`](crate::operation::detect_text::DetectTextInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::detect_text::DetectTextInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::detect_text::DetectTextInput {
            image: self.image,
            filters: self.filters,
        })
    }
}
