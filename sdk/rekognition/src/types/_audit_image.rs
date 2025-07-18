// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An image that is picked from the Face Liveness video and returned for audit trail purposes, returned as Base64-encoded bytes.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct AuditImage {
    /// <p>The Base64-encoded bytes representing an image selected from the Face Liveness video and returned for audit purposes.</p>
    pub bytes: ::std::option::Option<::aws_smithy_types::Blob>,
    /// <p>Provides the S3 bucket name and object name.</p>
    /// <p>The region for the S3 bucket containing the S3 object must match the region you use for Amazon Rekognition operations.</p>
    /// <p>For Amazon Rekognition to process an S3 object, the user must have permission to access the S3 object. For more information, see How Amazon Rekognition works with IAM in the Amazon Rekognition Developer Guide.</p>
    pub s3_object: ::std::option::Option<crate::types::S3Object>,
    /// <p>Identifies the bounding box around the label, face, text, object of interest, or personal protective equipment. The <code>left</code> (x-coordinate) and <code>top</code> (y-coordinate) are coordinates representing the top and left sides of the bounding box. Note that the upper-left corner of the image is the origin (0,0).</p>
    /// <p>The <code>top</code> and <code>left</code> values returned are ratios of the overall image size. For example, if the input image is 700x200 pixels, and the top-left coordinate of the bounding box is 350x50 pixels, the API returns a <code>left</code> value of 0.5 (350/700) and a <code>top</code> value of 0.25 (50/200).</p>
    /// <p>The <code>width</code> and <code>height</code> values represent the dimensions of the bounding box as a ratio of the overall image dimension. For example, if the input image is 700x200 pixels, and the bounding box width is 70 pixels, the width returned is 0.1.</p><note>
    /// <p>The bounding box coordinates can have negative values. For example, if Amazon Rekognition is able to detect a face that is at the image edge and is only partially visible, the service can return coordinates that are outside the image bounds and, depending on the image edge, you might get negative values or values greater than 1 for the <code>left</code> or <code>top</code> values.</p>
    /// </note>
    pub bounding_box: ::std::option::Option<crate::types::BoundingBox>,
}
impl AuditImage {
    /// <p>The Base64-encoded bytes representing an image selected from the Face Liveness video and returned for audit purposes.</p>
    pub fn bytes(&self) -> ::std::option::Option<&::aws_smithy_types::Blob> {
        self.bytes.as_ref()
    }
    /// <p>Provides the S3 bucket name and object name.</p>
    /// <p>The region for the S3 bucket containing the S3 object must match the region you use for Amazon Rekognition operations.</p>
    /// <p>For Amazon Rekognition to process an S3 object, the user must have permission to access the S3 object. For more information, see How Amazon Rekognition works with IAM in the Amazon Rekognition Developer Guide.</p>
    pub fn s3_object(&self) -> ::std::option::Option<&crate::types::S3Object> {
        self.s3_object.as_ref()
    }
    /// <p>Identifies the bounding box around the label, face, text, object of interest, or personal protective equipment. The <code>left</code> (x-coordinate) and <code>top</code> (y-coordinate) are coordinates representing the top and left sides of the bounding box. Note that the upper-left corner of the image is the origin (0,0).</p>
    /// <p>The <code>top</code> and <code>left</code> values returned are ratios of the overall image size. For example, if the input image is 700x200 pixels, and the top-left coordinate of the bounding box is 350x50 pixels, the API returns a <code>left</code> value of 0.5 (350/700) and a <code>top</code> value of 0.25 (50/200).</p>
    /// <p>The <code>width</code> and <code>height</code> values represent the dimensions of the bounding box as a ratio of the overall image dimension. For example, if the input image is 700x200 pixels, and the bounding box width is 70 pixels, the width returned is 0.1.</p><note>
    /// <p>The bounding box coordinates can have negative values. For example, if Amazon Rekognition is able to detect a face that is at the image edge and is only partially visible, the service can return coordinates that are outside the image bounds and, depending on the image edge, you might get negative values or values greater than 1 for the <code>left</code> or <code>top</code> values.</p>
    /// </note>
    pub fn bounding_box(&self) -> ::std::option::Option<&crate::types::BoundingBox> {
        self.bounding_box.as_ref()
    }
}
impl ::std::fmt::Debug for AuditImage {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("AuditImage");
        formatter.field("bytes", &"*** Sensitive Data Redacted ***");
        formatter.field("s3_object", &self.s3_object);
        formatter.field("bounding_box", &self.bounding_box);
        formatter.finish()
    }
}
impl AuditImage {
    /// Creates a new builder-style object to manufacture [`AuditImage`](crate::types::AuditImage).
    pub fn builder() -> crate::types::builders::AuditImageBuilder {
        crate::types::builders::AuditImageBuilder::default()
    }
}

/// A builder for [`AuditImage`](crate::types::AuditImage).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct AuditImageBuilder {
    pub(crate) bytes: ::std::option::Option<::aws_smithy_types::Blob>,
    pub(crate) s3_object: ::std::option::Option<crate::types::S3Object>,
    pub(crate) bounding_box: ::std::option::Option<crate::types::BoundingBox>,
}
impl AuditImageBuilder {
    /// <p>The Base64-encoded bytes representing an image selected from the Face Liveness video and returned for audit purposes.</p>
    pub fn bytes(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.bytes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Base64-encoded bytes representing an image selected from the Face Liveness video and returned for audit purposes.</p>
    pub fn set_bytes(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.bytes = input;
        self
    }
    /// <p>The Base64-encoded bytes representing an image selected from the Face Liveness video and returned for audit purposes.</p>
    pub fn get_bytes(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.bytes
    }
    /// <p>Provides the S3 bucket name and object name.</p>
    /// <p>The region for the S3 bucket containing the S3 object must match the region you use for Amazon Rekognition operations.</p>
    /// <p>For Amazon Rekognition to process an S3 object, the user must have permission to access the S3 object. For more information, see How Amazon Rekognition works with IAM in the Amazon Rekognition Developer Guide.</p>
    pub fn s3_object(mut self, input: crate::types::S3Object) -> Self {
        self.s3_object = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides the S3 bucket name and object name.</p>
    /// <p>The region for the S3 bucket containing the S3 object must match the region you use for Amazon Rekognition operations.</p>
    /// <p>For Amazon Rekognition to process an S3 object, the user must have permission to access the S3 object. For more information, see How Amazon Rekognition works with IAM in the Amazon Rekognition Developer Guide.</p>
    pub fn set_s3_object(mut self, input: ::std::option::Option<crate::types::S3Object>) -> Self {
        self.s3_object = input;
        self
    }
    /// <p>Provides the S3 bucket name and object name.</p>
    /// <p>The region for the S3 bucket containing the S3 object must match the region you use for Amazon Rekognition operations.</p>
    /// <p>For Amazon Rekognition to process an S3 object, the user must have permission to access the S3 object. For more information, see How Amazon Rekognition works with IAM in the Amazon Rekognition Developer Guide.</p>
    pub fn get_s3_object(&self) -> &::std::option::Option<crate::types::S3Object> {
        &self.s3_object
    }
    /// <p>Identifies the bounding box around the label, face, text, object of interest, or personal protective equipment. The <code>left</code> (x-coordinate) and <code>top</code> (y-coordinate) are coordinates representing the top and left sides of the bounding box. Note that the upper-left corner of the image is the origin (0,0).</p>
    /// <p>The <code>top</code> and <code>left</code> values returned are ratios of the overall image size. For example, if the input image is 700x200 pixels, and the top-left coordinate of the bounding box is 350x50 pixels, the API returns a <code>left</code> value of 0.5 (350/700) and a <code>top</code> value of 0.25 (50/200).</p>
    /// <p>The <code>width</code> and <code>height</code> values represent the dimensions of the bounding box as a ratio of the overall image dimension. For example, if the input image is 700x200 pixels, and the bounding box width is 70 pixels, the width returned is 0.1.</p><note>
    /// <p>The bounding box coordinates can have negative values. For example, if Amazon Rekognition is able to detect a face that is at the image edge and is only partially visible, the service can return coordinates that are outside the image bounds and, depending on the image edge, you might get negative values or values greater than 1 for the <code>left</code> or <code>top</code> values.</p>
    /// </note>
    pub fn bounding_box(mut self, input: crate::types::BoundingBox) -> Self {
        self.bounding_box = ::std::option::Option::Some(input);
        self
    }
    /// <p>Identifies the bounding box around the label, face, text, object of interest, or personal protective equipment. The <code>left</code> (x-coordinate) and <code>top</code> (y-coordinate) are coordinates representing the top and left sides of the bounding box. Note that the upper-left corner of the image is the origin (0,0).</p>
    /// <p>The <code>top</code> and <code>left</code> values returned are ratios of the overall image size. For example, if the input image is 700x200 pixels, and the top-left coordinate of the bounding box is 350x50 pixels, the API returns a <code>left</code> value of 0.5 (350/700) and a <code>top</code> value of 0.25 (50/200).</p>
    /// <p>The <code>width</code> and <code>height</code> values represent the dimensions of the bounding box as a ratio of the overall image dimension. For example, if the input image is 700x200 pixels, and the bounding box width is 70 pixels, the width returned is 0.1.</p><note>
    /// <p>The bounding box coordinates can have negative values. For example, if Amazon Rekognition is able to detect a face that is at the image edge and is only partially visible, the service can return coordinates that are outside the image bounds and, depending on the image edge, you might get negative values or values greater than 1 for the <code>left</code> or <code>top</code> values.</p>
    /// </note>
    pub fn set_bounding_box(mut self, input: ::std::option::Option<crate::types::BoundingBox>) -> Self {
        self.bounding_box = input;
        self
    }
    /// <p>Identifies the bounding box around the label, face, text, object of interest, or personal protective equipment. The <code>left</code> (x-coordinate) and <code>top</code> (y-coordinate) are coordinates representing the top and left sides of the bounding box. Note that the upper-left corner of the image is the origin (0,0).</p>
    /// <p>The <code>top</code> and <code>left</code> values returned are ratios of the overall image size. For example, if the input image is 700x200 pixels, and the top-left coordinate of the bounding box is 350x50 pixels, the API returns a <code>left</code> value of 0.5 (350/700) and a <code>top</code> value of 0.25 (50/200).</p>
    /// <p>The <code>width</code> and <code>height</code> values represent the dimensions of the bounding box as a ratio of the overall image dimension. For example, if the input image is 700x200 pixels, and the bounding box width is 70 pixels, the width returned is 0.1.</p><note>
    /// <p>The bounding box coordinates can have negative values. For example, if Amazon Rekognition is able to detect a face that is at the image edge and is only partially visible, the service can return coordinates that are outside the image bounds and, depending on the image edge, you might get negative values or values greater than 1 for the <code>left</code> or <code>top</code> values.</p>
    /// </note>
    pub fn get_bounding_box(&self) -> &::std::option::Option<crate::types::BoundingBox> {
        &self.bounding_box
    }
    /// Consumes the builder and constructs a [`AuditImage`](crate::types::AuditImage).
    pub fn build(self) -> crate::types::AuditImage {
        crate::types::AuditImage {
            bytes: self.bytes,
            s3_object: self.s3_object,
            bounding_box: self.bounding_box,
        }
    }
}
impl ::std::fmt::Debug for AuditImageBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("AuditImageBuilder");
        formatter.field("bytes", &"*** Sensitive Data Redacted ***");
        formatter.field("s3_object", &self.s3_object);
        formatter.field("bounding_box", &self.bounding_box);
        formatter.finish()
    }
}
