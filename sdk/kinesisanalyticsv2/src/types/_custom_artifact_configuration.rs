// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies dependency JARs, as well as JAR files that contain user-defined functions (UDF).</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CustomArtifactConfiguration {
    /// <p><code>UDF</code> stands for user-defined functions. This type of artifact must be in an S3 bucket. A <code>DEPENDENCY_JAR</code> can be in either Maven or an S3 bucket.</p>
    pub artifact_type: crate::types::ArtifactType,
    /// <p>For a Managed Service for Apache Flink application provides a description of an Amazon S3 object, including the Amazon Resource Name (ARN) of the S3 bucket, the name of the Amazon S3 object that contains the data, and the version number of the Amazon S3 object that contains the data.</p>
    pub s3_content_location: ::std::option::Option<crate::types::S3ContentLocation>,
    /// <p>The parameters required to fully specify a Maven reference.</p>
    pub maven_reference: ::std::option::Option<crate::types::MavenReference>,
}
impl CustomArtifactConfiguration {
    /// <p><code>UDF</code> stands for user-defined functions. This type of artifact must be in an S3 bucket. A <code>DEPENDENCY_JAR</code> can be in either Maven or an S3 bucket.</p>
    pub fn artifact_type(&self) -> &crate::types::ArtifactType {
        &self.artifact_type
    }
    /// <p>For a Managed Service for Apache Flink application provides a description of an Amazon S3 object, including the Amazon Resource Name (ARN) of the S3 bucket, the name of the Amazon S3 object that contains the data, and the version number of the Amazon S3 object that contains the data.</p>
    pub fn s3_content_location(&self) -> ::std::option::Option<&crate::types::S3ContentLocation> {
        self.s3_content_location.as_ref()
    }
    /// <p>The parameters required to fully specify a Maven reference.</p>
    pub fn maven_reference(&self) -> ::std::option::Option<&crate::types::MavenReference> {
        self.maven_reference.as_ref()
    }
}
impl CustomArtifactConfiguration {
    /// Creates a new builder-style object to manufacture [`CustomArtifactConfiguration`](crate::types::CustomArtifactConfiguration).
    pub fn builder() -> crate::types::builders::CustomArtifactConfigurationBuilder {
        crate::types::builders::CustomArtifactConfigurationBuilder::default()
    }
}

/// A builder for [`CustomArtifactConfiguration`](crate::types::CustomArtifactConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CustomArtifactConfigurationBuilder {
    pub(crate) artifact_type: ::std::option::Option<crate::types::ArtifactType>,
    pub(crate) s3_content_location: ::std::option::Option<crate::types::S3ContentLocation>,
    pub(crate) maven_reference: ::std::option::Option<crate::types::MavenReference>,
}
impl CustomArtifactConfigurationBuilder {
    /// <p><code>UDF</code> stands for user-defined functions. This type of artifact must be in an S3 bucket. A <code>DEPENDENCY_JAR</code> can be in either Maven or an S3 bucket.</p>
    /// This field is required.
    pub fn artifact_type(mut self, input: crate::types::ArtifactType) -> Self {
        self.artifact_type = ::std::option::Option::Some(input);
        self
    }
    /// <p><code>UDF</code> stands for user-defined functions. This type of artifact must be in an S3 bucket. A <code>DEPENDENCY_JAR</code> can be in either Maven or an S3 bucket.</p>
    pub fn set_artifact_type(mut self, input: ::std::option::Option<crate::types::ArtifactType>) -> Self {
        self.artifact_type = input;
        self
    }
    /// <p><code>UDF</code> stands for user-defined functions. This type of artifact must be in an S3 bucket. A <code>DEPENDENCY_JAR</code> can be in either Maven or an S3 bucket.</p>
    pub fn get_artifact_type(&self) -> &::std::option::Option<crate::types::ArtifactType> {
        &self.artifact_type
    }
    /// <p>For a Managed Service for Apache Flink application provides a description of an Amazon S3 object, including the Amazon Resource Name (ARN) of the S3 bucket, the name of the Amazon S3 object that contains the data, and the version number of the Amazon S3 object that contains the data.</p>
    pub fn s3_content_location(mut self, input: crate::types::S3ContentLocation) -> Self {
        self.s3_content_location = ::std::option::Option::Some(input);
        self
    }
    /// <p>For a Managed Service for Apache Flink application provides a description of an Amazon S3 object, including the Amazon Resource Name (ARN) of the S3 bucket, the name of the Amazon S3 object that contains the data, and the version number of the Amazon S3 object that contains the data.</p>
    pub fn set_s3_content_location(mut self, input: ::std::option::Option<crate::types::S3ContentLocation>) -> Self {
        self.s3_content_location = input;
        self
    }
    /// <p>For a Managed Service for Apache Flink application provides a description of an Amazon S3 object, including the Amazon Resource Name (ARN) of the S3 bucket, the name of the Amazon S3 object that contains the data, and the version number of the Amazon S3 object that contains the data.</p>
    pub fn get_s3_content_location(&self) -> &::std::option::Option<crate::types::S3ContentLocation> {
        &self.s3_content_location
    }
    /// <p>The parameters required to fully specify a Maven reference.</p>
    pub fn maven_reference(mut self, input: crate::types::MavenReference) -> Self {
        self.maven_reference = ::std::option::Option::Some(input);
        self
    }
    /// <p>The parameters required to fully specify a Maven reference.</p>
    pub fn set_maven_reference(mut self, input: ::std::option::Option<crate::types::MavenReference>) -> Self {
        self.maven_reference = input;
        self
    }
    /// <p>The parameters required to fully specify a Maven reference.</p>
    pub fn get_maven_reference(&self) -> &::std::option::Option<crate::types::MavenReference> {
        &self.maven_reference
    }
    /// Consumes the builder and constructs a [`CustomArtifactConfiguration`](crate::types::CustomArtifactConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`artifact_type`](crate::types::builders::CustomArtifactConfigurationBuilder::artifact_type)
    pub fn build(self) -> ::std::result::Result<crate::types::CustomArtifactConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CustomArtifactConfiguration {
            artifact_type: self.artifact_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "artifact_type",
                    "artifact_type was not specified but it is required when building CustomArtifactConfiguration",
                )
            })?,
            s3_content_location: self.s3_content_location,
            maven_reference: self.maven_reference,
        })
    }
}
