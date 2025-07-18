// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SearchUsersByImageInput {
    /// <p>The ID of an existing collection containing the UserID.</p>
    pub collection_id: ::std::option::Option<::std::string::String>,
    /// <p>Provides the input image either as bytes or an S3 object.</p>
    /// <p>You pass image bytes to an Amazon Rekognition API operation by using the <code>Bytes</code> property. For example, you would use the <code>Bytes</code> property to pass an image loaded from a local file system. Image bytes passed by using the <code>Bytes</code> property must be base64-encoded. Your code may not need to encode image bytes if you are using an AWS SDK to call Amazon Rekognition API operations.</p>
    /// <p>For more information, see Analyzing an Image Loaded from a Local File System in the Amazon Rekognition Developer Guide.</p>
    /// <p>You pass images stored in an S3 bucket to an Amazon Rekognition API operation by using the <code>S3Object</code> property. Images stored in an S3 bucket do not need to be base64-encoded.</p>
    /// <p>The region for the S3 bucket containing the S3 object must match the region you use for Amazon Rekognition operations.</p>
    /// <p>If you use the AWS CLI to call Amazon Rekognition operations, passing image bytes using the Bytes property is not supported. You must first upload the image to an Amazon S3 bucket and then call the operation using the S3Object property.</p>
    /// <p>For Amazon Rekognition to process an S3 object, the user must have permission to access the S3 object. For more information, see How Amazon Rekognition works with IAM in the Amazon Rekognition Developer Guide.</p>
    pub image: ::std::option::Option<crate::types::Image>,
    /// <p>Specifies the minimum confidence in the UserID match to return. Default value is 80.</p>
    pub user_match_threshold: ::std::option::Option<f32>,
    /// <p>Maximum number of UserIDs to return.</p>
    pub max_users: ::std::option::Option<i32>,
    /// <p>A filter that specifies a quality bar for how much filtering is done to identify faces. Filtered faces aren't searched for in the collection. The default value is NONE.</p>
    pub quality_filter: ::std::option::Option<crate::types::QualityFilter>,
}
impl SearchUsersByImageInput {
    /// <p>The ID of an existing collection containing the UserID.</p>
    pub fn collection_id(&self) -> ::std::option::Option<&str> {
        self.collection_id.as_deref()
    }
    /// <p>Provides the input image either as bytes or an S3 object.</p>
    /// <p>You pass image bytes to an Amazon Rekognition API operation by using the <code>Bytes</code> property. For example, you would use the <code>Bytes</code> property to pass an image loaded from a local file system. Image bytes passed by using the <code>Bytes</code> property must be base64-encoded. Your code may not need to encode image bytes if you are using an AWS SDK to call Amazon Rekognition API operations.</p>
    /// <p>For more information, see Analyzing an Image Loaded from a Local File System in the Amazon Rekognition Developer Guide.</p>
    /// <p>You pass images stored in an S3 bucket to an Amazon Rekognition API operation by using the <code>S3Object</code> property. Images stored in an S3 bucket do not need to be base64-encoded.</p>
    /// <p>The region for the S3 bucket containing the S3 object must match the region you use for Amazon Rekognition operations.</p>
    /// <p>If you use the AWS CLI to call Amazon Rekognition operations, passing image bytes using the Bytes property is not supported. You must first upload the image to an Amazon S3 bucket and then call the operation using the S3Object property.</p>
    /// <p>For Amazon Rekognition to process an S3 object, the user must have permission to access the S3 object. For more information, see How Amazon Rekognition works with IAM in the Amazon Rekognition Developer Guide.</p>
    pub fn image(&self) -> ::std::option::Option<&crate::types::Image> {
        self.image.as_ref()
    }
    /// <p>Specifies the minimum confidence in the UserID match to return. Default value is 80.</p>
    pub fn user_match_threshold(&self) -> ::std::option::Option<f32> {
        self.user_match_threshold
    }
    /// <p>Maximum number of UserIDs to return.</p>
    pub fn max_users(&self) -> ::std::option::Option<i32> {
        self.max_users
    }
    /// <p>A filter that specifies a quality bar for how much filtering is done to identify faces. Filtered faces aren't searched for in the collection. The default value is NONE.</p>
    pub fn quality_filter(&self) -> ::std::option::Option<&crate::types::QualityFilter> {
        self.quality_filter.as_ref()
    }
}
impl SearchUsersByImageInput {
    /// Creates a new builder-style object to manufacture [`SearchUsersByImageInput`](crate::operation::search_users_by_image::SearchUsersByImageInput).
    pub fn builder() -> crate::operation::search_users_by_image::builders::SearchUsersByImageInputBuilder {
        crate::operation::search_users_by_image::builders::SearchUsersByImageInputBuilder::default()
    }
}

/// A builder for [`SearchUsersByImageInput`](crate::operation::search_users_by_image::SearchUsersByImageInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SearchUsersByImageInputBuilder {
    pub(crate) collection_id: ::std::option::Option<::std::string::String>,
    pub(crate) image: ::std::option::Option<crate::types::Image>,
    pub(crate) user_match_threshold: ::std::option::Option<f32>,
    pub(crate) max_users: ::std::option::Option<i32>,
    pub(crate) quality_filter: ::std::option::Option<crate::types::QualityFilter>,
}
impl SearchUsersByImageInputBuilder {
    /// <p>The ID of an existing collection containing the UserID.</p>
    /// This field is required.
    pub fn collection_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.collection_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of an existing collection containing the UserID.</p>
    pub fn set_collection_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.collection_id = input;
        self
    }
    /// <p>The ID of an existing collection containing the UserID.</p>
    pub fn get_collection_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.collection_id
    }
    /// <p>Provides the input image either as bytes or an S3 object.</p>
    /// <p>You pass image bytes to an Amazon Rekognition API operation by using the <code>Bytes</code> property. For example, you would use the <code>Bytes</code> property to pass an image loaded from a local file system. Image bytes passed by using the <code>Bytes</code> property must be base64-encoded. Your code may not need to encode image bytes if you are using an AWS SDK to call Amazon Rekognition API operations.</p>
    /// <p>For more information, see Analyzing an Image Loaded from a Local File System in the Amazon Rekognition Developer Guide.</p>
    /// <p>You pass images stored in an S3 bucket to an Amazon Rekognition API operation by using the <code>S3Object</code> property. Images stored in an S3 bucket do not need to be base64-encoded.</p>
    /// <p>The region for the S3 bucket containing the S3 object must match the region you use for Amazon Rekognition operations.</p>
    /// <p>If you use the AWS CLI to call Amazon Rekognition operations, passing image bytes using the Bytes property is not supported. You must first upload the image to an Amazon S3 bucket and then call the operation using the S3Object property.</p>
    /// <p>For Amazon Rekognition to process an S3 object, the user must have permission to access the S3 object. For more information, see How Amazon Rekognition works with IAM in the Amazon Rekognition Developer Guide.</p>
    /// This field is required.
    pub fn image(mut self, input: crate::types::Image) -> Self {
        self.image = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides the input image either as bytes or an S3 object.</p>
    /// <p>You pass image bytes to an Amazon Rekognition API operation by using the <code>Bytes</code> property. For example, you would use the <code>Bytes</code> property to pass an image loaded from a local file system. Image bytes passed by using the <code>Bytes</code> property must be base64-encoded. Your code may not need to encode image bytes if you are using an AWS SDK to call Amazon Rekognition API operations.</p>
    /// <p>For more information, see Analyzing an Image Loaded from a Local File System in the Amazon Rekognition Developer Guide.</p>
    /// <p>You pass images stored in an S3 bucket to an Amazon Rekognition API operation by using the <code>S3Object</code> property. Images stored in an S3 bucket do not need to be base64-encoded.</p>
    /// <p>The region for the S3 bucket containing the S3 object must match the region you use for Amazon Rekognition operations.</p>
    /// <p>If you use the AWS CLI to call Amazon Rekognition operations, passing image bytes using the Bytes property is not supported. You must first upload the image to an Amazon S3 bucket and then call the operation using the S3Object property.</p>
    /// <p>For Amazon Rekognition to process an S3 object, the user must have permission to access the S3 object. For more information, see How Amazon Rekognition works with IAM in the Amazon Rekognition Developer Guide.</p>
    pub fn set_image(mut self, input: ::std::option::Option<crate::types::Image>) -> Self {
        self.image = input;
        self
    }
    /// <p>Provides the input image either as bytes or an S3 object.</p>
    /// <p>You pass image bytes to an Amazon Rekognition API operation by using the <code>Bytes</code> property. For example, you would use the <code>Bytes</code> property to pass an image loaded from a local file system. Image bytes passed by using the <code>Bytes</code> property must be base64-encoded. Your code may not need to encode image bytes if you are using an AWS SDK to call Amazon Rekognition API operations.</p>
    /// <p>For more information, see Analyzing an Image Loaded from a Local File System in the Amazon Rekognition Developer Guide.</p>
    /// <p>You pass images stored in an S3 bucket to an Amazon Rekognition API operation by using the <code>S3Object</code> property. Images stored in an S3 bucket do not need to be base64-encoded.</p>
    /// <p>The region for the S3 bucket containing the S3 object must match the region you use for Amazon Rekognition operations.</p>
    /// <p>If you use the AWS CLI to call Amazon Rekognition operations, passing image bytes using the Bytes property is not supported. You must first upload the image to an Amazon S3 bucket and then call the operation using the S3Object property.</p>
    /// <p>For Amazon Rekognition to process an S3 object, the user must have permission to access the S3 object. For more information, see How Amazon Rekognition works with IAM in the Amazon Rekognition Developer Guide.</p>
    pub fn get_image(&self) -> &::std::option::Option<crate::types::Image> {
        &self.image
    }
    /// <p>Specifies the minimum confidence in the UserID match to return. Default value is 80.</p>
    pub fn user_match_threshold(mut self, input: f32) -> Self {
        self.user_match_threshold = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the minimum confidence in the UserID match to return. Default value is 80.</p>
    pub fn set_user_match_threshold(mut self, input: ::std::option::Option<f32>) -> Self {
        self.user_match_threshold = input;
        self
    }
    /// <p>Specifies the minimum confidence in the UserID match to return. Default value is 80.</p>
    pub fn get_user_match_threshold(&self) -> &::std::option::Option<f32> {
        &self.user_match_threshold
    }
    /// <p>Maximum number of UserIDs to return.</p>
    pub fn max_users(mut self, input: i32) -> Self {
        self.max_users = ::std::option::Option::Some(input);
        self
    }
    /// <p>Maximum number of UserIDs to return.</p>
    pub fn set_max_users(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_users = input;
        self
    }
    /// <p>Maximum number of UserIDs to return.</p>
    pub fn get_max_users(&self) -> &::std::option::Option<i32> {
        &self.max_users
    }
    /// <p>A filter that specifies a quality bar for how much filtering is done to identify faces. Filtered faces aren't searched for in the collection. The default value is NONE.</p>
    pub fn quality_filter(mut self, input: crate::types::QualityFilter) -> Self {
        self.quality_filter = ::std::option::Option::Some(input);
        self
    }
    /// <p>A filter that specifies a quality bar for how much filtering is done to identify faces. Filtered faces aren't searched for in the collection. The default value is NONE.</p>
    pub fn set_quality_filter(mut self, input: ::std::option::Option<crate::types::QualityFilter>) -> Self {
        self.quality_filter = input;
        self
    }
    /// <p>A filter that specifies a quality bar for how much filtering is done to identify faces. Filtered faces aren't searched for in the collection. The default value is NONE.</p>
    pub fn get_quality_filter(&self) -> &::std::option::Option<crate::types::QualityFilter> {
        &self.quality_filter
    }
    /// Consumes the builder and constructs a [`SearchUsersByImageInput`](crate::operation::search_users_by_image::SearchUsersByImageInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::search_users_by_image::SearchUsersByImageInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::search_users_by_image::SearchUsersByImageInput {
            collection_id: self.collection_id,
            image: self.image,
            user_match_threshold: self.user_match_threshold,
            max_users: self.max_users,
            quality_filter: self.quality_filter,
        })
    }
}
