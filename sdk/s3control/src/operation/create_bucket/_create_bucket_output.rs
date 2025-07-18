// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateBucketOutput {
    /// <p>The location of the bucket.</p>
    pub location: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the bucket.</p>
    /// <p>For using this parameter with Amazon S3 on Outposts with the REST API, you must specify the name and the x-amz-outpost-id as well.</p>
    /// <p>For using this parameter with S3 on Outposts with the Amazon Web Services SDK and CLI, you must specify the ARN of the bucket accessed in the format <code>arn:aws:s3-outposts:<region>
    /// :
    /// <account-id>
    /// :outpost/
    /// <outpost-id>
    /// /bucket/
    /// <my-bucket-name></my-bucket-name>
    /// </outpost-id>
    /// </account-id>
    /// </region></code>. For example, to access the bucket <code>reports</code> through Outpost <code>my-outpost</code> owned by account <code>123456789012</code> in Region <code>us-west-2</code>, use the URL encoding of <code>arn:aws:s3-outposts:us-west-2:123456789012:outpost/my-outpost/bucket/reports</code>. The value must be URL encoded.</p>
    pub bucket_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateBucketOutput {
    /// <p>The location of the bucket.</p>
    pub fn location(&self) -> ::std::option::Option<&str> {
        self.location.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the bucket.</p>
    /// <p>For using this parameter with Amazon S3 on Outposts with the REST API, you must specify the name and the x-amz-outpost-id as well.</p>
    /// <p>For using this parameter with S3 on Outposts with the Amazon Web Services SDK and CLI, you must specify the ARN of the bucket accessed in the format <code>arn:aws:s3-outposts:<region>
    /// :
    /// <account-id>
    /// :outpost/
    /// <outpost-id>
    /// /bucket/
    /// <my-bucket-name></my-bucket-name>
    /// </outpost-id>
    /// </account-id>
    /// </region></code>. For example, to access the bucket <code>reports</code> through Outpost <code>my-outpost</code> owned by account <code>123456789012</code> in Region <code>us-west-2</code>, use the URL encoding of <code>arn:aws:s3-outposts:us-west-2:123456789012:outpost/my-outpost/bucket/reports</code>. The value must be URL encoded.</p>
    pub fn bucket_arn(&self) -> ::std::option::Option<&str> {
        self.bucket_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateBucketOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateBucketOutput {
    /// Creates a new builder-style object to manufacture [`CreateBucketOutput`](crate::operation::create_bucket::CreateBucketOutput).
    pub fn builder() -> crate::operation::create_bucket::builders::CreateBucketOutputBuilder {
        crate::operation::create_bucket::builders::CreateBucketOutputBuilder::default()
    }
}

/// A builder for [`CreateBucketOutput`](crate::operation::create_bucket::CreateBucketOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateBucketOutputBuilder {
    pub(crate) location: ::std::option::Option<::std::string::String>,
    pub(crate) bucket_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateBucketOutputBuilder {
    /// <p>The location of the bucket.</p>
    pub fn location(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.location = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The location of the bucket.</p>
    pub fn set_location(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.location = input;
        self
    }
    /// <p>The location of the bucket.</p>
    pub fn get_location(&self) -> &::std::option::Option<::std::string::String> {
        &self.location
    }
    /// <p>The Amazon Resource Name (ARN) of the bucket.</p>
    /// <p>For using this parameter with Amazon S3 on Outposts with the REST API, you must specify the name and the x-amz-outpost-id as well.</p>
    /// <p>For using this parameter with S3 on Outposts with the Amazon Web Services SDK and CLI, you must specify the ARN of the bucket accessed in the format <code>arn:aws:s3-outposts:<region>
    /// :
    /// <account-id>
    /// :outpost/
    /// <outpost-id>
    /// /bucket/
    /// <my-bucket-name></my-bucket-name>
    /// </outpost-id>
    /// </account-id>
    /// </region></code>. For example, to access the bucket <code>reports</code> through Outpost <code>my-outpost</code> owned by account <code>123456789012</code> in Region <code>us-west-2</code>, use the URL encoding of <code>arn:aws:s3-outposts:us-west-2:123456789012:outpost/my-outpost/bucket/reports</code>. The value must be URL encoded.</p>
    pub fn bucket_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the bucket.</p>
    /// <p>For using this parameter with Amazon S3 on Outposts with the REST API, you must specify the name and the x-amz-outpost-id as well.</p>
    /// <p>For using this parameter with S3 on Outposts with the Amazon Web Services SDK and CLI, you must specify the ARN of the bucket accessed in the format <code>arn:aws:s3-outposts:<region>
    /// :
    /// <account-id>
    /// :outpost/
    /// <outpost-id>
    /// /bucket/
    /// <my-bucket-name></my-bucket-name>
    /// </outpost-id>
    /// </account-id>
    /// </region></code>. For example, to access the bucket <code>reports</code> through Outpost <code>my-outpost</code> owned by account <code>123456789012</code> in Region <code>us-west-2</code>, use the URL encoding of <code>arn:aws:s3-outposts:us-west-2:123456789012:outpost/my-outpost/bucket/reports</code>. The value must be URL encoded.</p>
    pub fn set_bucket_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the bucket.</p>
    /// <p>For using this parameter with Amazon S3 on Outposts with the REST API, you must specify the name and the x-amz-outpost-id as well.</p>
    /// <p>For using this parameter with S3 on Outposts with the Amazon Web Services SDK and CLI, you must specify the ARN of the bucket accessed in the format <code>arn:aws:s3-outposts:<region>
    /// :
    /// <account-id>
    /// :outpost/
    /// <outpost-id>
    /// /bucket/
    /// <my-bucket-name></my-bucket-name>
    /// </outpost-id>
    /// </account-id>
    /// </region></code>. For example, to access the bucket <code>reports</code> through Outpost <code>my-outpost</code> owned by account <code>123456789012</code> in Region <code>us-west-2</code>, use the URL encoding of <code>arn:aws:s3-outposts:us-west-2:123456789012:outpost/my-outpost/bucket/reports</code>. The value must be URL encoded.</p>
    pub fn get_bucket_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateBucketOutput`](crate::operation::create_bucket::CreateBucketOutput).
    pub fn build(self) -> crate::operation::create_bucket::CreateBucketOutput {
        crate::operation::create_bucket::CreateBucketOutput {
            location: self.location,
            bucket_arn: self.bucket_arn,
            _request_id: self._request_id,
        }
    }
}
