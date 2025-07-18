// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the results for a media analysis job created with StartMediaAnalysisJob.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MediaAnalysisResults {
    /// <p>Provides the S3 bucket name and object name.</p>
    /// <p>The region for the S3 bucket containing the S3 object must match the region you use for Amazon Rekognition operations.</p>
    /// <p>For Amazon Rekognition to process an S3 object, the user must have permission to access the S3 object. For more information, see How Amazon Rekognition works with IAM in the Amazon Rekognition Developer Guide.</p>
    pub s3_object: ::std::option::Option<crate::types::S3Object>,
    /// <p>Information about the model versions for the features selected in a given job.</p>
    pub model_versions: ::std::option::Option<crate::types::MediaAnalysisModelVersions>,
}
impl MediaAnalysisResults {
    /// <p>Provides the S3 bucket name and object name.</p>
    /// <p>The region for the S3 bucket containing the S3 object must match the region you use for Amazon Rekognition operations.</p>
    /// <p>For Amazon Rekognition to process an S3 object, the user must have permission to access the S3 object. For more information, see How Amazon Rekognition works with IAM in the Amazon Rekognition Developer Guide.</p>
    pub fn s3_object(&self) -> ::std::option::Option<&crate::types::S3Object> {
        self.s3_object.as_ref()
    }
    /// <p>Information about the model versions for the features selected in a given job.</p>
    pub fn model_versions(&self) -> ::std::option::Option<&crate::types::MediaAnalysisModelVersions> {
        self.model_versions.as_ref()
    }
}
impl MediaAnalysisResults {
    /// Creates a new builder-style object to manufacture [`MediaAnalysisResults`](crate::types::MediaAnalysisResults).
    pub fn builder() -> crate::types::builders::MediaAnalysisResultsBuilder {
        crate::types::builders::MediaAnalysisResultsBuilder::default()
    }
}

/// A builder for [`MediaAnalysisResults`](crate::types::MediaAnalysisResults).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MediaAnalysisResultsBuilder {
    pub(crate) s3_object: ::std::option::Option<crate::types::S3Object>,
    pub(crate) model_versions: ::std::option::Option<crate::types::MediaAnalysisModelVersions>,
}
impl MediaAnalysisResultsBuilder {
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
    /// <p>Information about the model versions for the features selected in a given job.</p>
    pub fn model_versions(mut self, input: crate::types::MediaAnalysisModelVersions) -> Self {
        self.model_versions = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the model versions for the features selected in a given job.</p>
    pub fn set_model_versions(mut self, input: ::std::option::Option<crate::types::MediaAnalysisModelVersions>) -> Self {
        self.model_versions = input;
        self
    }
    /// <p>Information about the model versions for the features selected in a given job.</p>
    pub fn get_model_versions(&self) -> &::std::option::Option<crate::types::MediaAnalysisModelVersions> {
        &self.model_versions
    }
    /// Consumes the builder and constructs a [`MediaAnalysisResults`](crate::types::MediaAnalysisResults).
    pub fn build(self) -> crate::types::MediaAnalysisResults {
        crate::types::MediaAnalysisResults {
            s3_object: self.s3_object,
            model_versions: self.model_versions,
        }
    }
}
