// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The input document, either as bytes or as an S3 object.</p>
/// <p>You pass image bytes to an Amazon Textract API operation by using the <code>Bytes</code> property. For example, you would use the <code>Bytes</code> property to pass a document loaded from a local file system. Image bytes passed by using the <code>Bytes</code> property must be base64 encoded. Your code might not need to encode document file bytes if you're using an AWS SDK to call Amazon Textract API operations.</p>
/// <p>You pass images stored in an S3 bucket to an Amazon Textract API operation by using the <code>S3Object</code> property. Documents stored in an S3 bucket don't need to be base64 encoded.</p>
/// <p>The AWS Region for the S3 bucket that contains the S3 object must match the AWS Region that you use for Amazon Textract operations.</p>
/// <p>If you use the AWS CLI to call Amazon Textract operations, passing image bytes using the Bytes property isn't supported. You must first upload the document to an Amazon S3 bucket, and then call the operation using the S3Object property.</p>
/// <p>For Amazon Textract to process an S3 object, the user must have permission to access the S3 object.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Document {
    /// <p>A blob of base64-encoded document bytes. The maximum size of a document that's provided in a blob of bytes is 5 MB. The document bytes must be in PNG or JPEG format.</p>
    /// <p>If you're using an AWS SDK to call Amazon Textract, you might not need to base64-encode image bytes passed using the <code>Bytes</code> field.</p>
    pub bytes: ::std::option::Option<::aws_smithy_types::Blob>,
    /// <p>Identifies an S3 object as the document source. The maximum size of a document that's stored in an S3 bucket is 5 MB.</p>
    pub s3_object: ::std::option::Option<crate::types::S3Object>,
}
impl Document {
    /// <p>A blob of base64-encoded document bytes. The maximum size of a document that's provided in a blob of bytes is 5 MB. The document bytes must be in PNG or JPEG format.</p>
    /// <p>If you're using an AWS SDK to call Amazon Textract, you might not need to base64-encode image bytes passed using the <code>Bytes</code> field.</p>
    pub fn bytes(&self) -> ::std::option::Option<&::aws_smithy_types::Blob> {
        self.bytes.as_ref()
    }
    /// <p>Identifies an S3 object as the document source. The maximum size of a document that's stored in an S3 bucket is 5 MB.</p>
    pub fn s3_object(&self) -> ::std::option::Option<&crate::types::S3Object> {
        self.s3_object.as_ref()
    }
}
impl Document {
    /// Creates a new builder-style object to manufacture [`Document`](crate::types::Document).
    pub fn builder() -> crate::types::builders::DocumentBuilder {
        crate::types::builders::DocumentBuilder::default()
    }
}

/// A builder for [`Document`](crate::types::Document).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DocumentBuilder {
    pub(crate) bytes: ::std::option::Option<::aws_smithy_types::Blob>,
    pub(crate) s3_object: ::std::option::Option<crate::types::S3Object>,
}
impl DocumentBuilder {
    /// <p>A blob of base64-encoded document bytes. The maximum size of a document that's provided in a blob of bytes is 5 MB. The document bytes must be in PNG or JPEG format.</p>
    /// <p>If you're using an AWS SDK to call Amazon Textract, you might not need to base64-encode image bytes passed using the <code>Bytes</code> field.</p>
    pub fn bytes(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.bytes = ::std::option::Option::Some(input);
        self
    }
    /// <p>A blob of base64-encoded document bytes. The maximum size of a document that's provided in a blob of bytes is 5 MB. The document bytes must be in PNG or JPEG format.</p>
    /// <p>If you're using an AWS SDK to call Amazon Textract, you might not need to base64-encode image bytes passed using the <code>Bytes</code> field.</p>
    pub fn set_bytes(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.bytes = input;
        self
    }
    /// <p>A blob of base64-encoded document bytes. The maximum size of a document that's provided in a blob of bytes is 5 MB. The document bytes must be in PNG or JPEG format.</p>
    /// <p>If you're using an AWS SDK to call Amazon Textract, you might not need to base64-encode image bytes passed using the <code>Bytes</code> field.</p>
    pub fn get_bytes(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.bytes
    }
    /// <p>Identifies an S3 object as the document source. The maximum size of a document that's stored in an S3 bucket is 5 MB.</p>
    pub fn s3_object(mut self, input: crate::types::S3Object) -> Self {
        self.s3_object = ::std::option::Option::Some(input);
        self
    }
    /// <p>Identifies an S3 object as the document source. The maximum size of a document that's stored in an S3 bucket is 5 MB.</p>
    pub fn set_s3_object(mut self, input: ::std::option::Option<crate::types::S3Object>) -> Self {
        self.s3_object = input;
        self
    }
    /// <p>Identifies an S3 object as the document source. The maximum size of a document that's stored in an S3 bucket is 5 MB.</p>
    pub fn get_s3_object(&self) -> &::std::option::Option<crate::types::S3Object> {
        &self.s3_object
    }
    /// Consumes the builder and constructs a [`Document`](crate::types::Document).
    pub fn build(self) -> crate::types::Document {
        crate::types::Document {
            bytes: self.bytes,
            s3_object: self.s3_object,
        }
    }
}
