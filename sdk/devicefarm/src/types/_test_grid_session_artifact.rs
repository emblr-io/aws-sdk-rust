// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Artifacts are video and other files that are produced in the process of running a browser in an automated context.</p><note>
/// <p>Video elements might be broken up into multiple artifacts as they grow in size during creation.</p>
/// </note>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct TestGridSessionArtifact {
    /// <p>The file name of the artifact.</p>
    pub filename: ::std::option::Option<::std::string::String>,
    /// <p>The kind of artifact.</p>
    pub r#type: ::std::option::Option<crate::types::TestGridSessionArtifactType>,
    /// <p>A semi-stable URL to the content of the object.</p>
    pub url: ::std::option::Option<::std::string::String>,
}
impl TestGridSessionArtifact {
    /// <p>The file name of the artifact.</p>
    pub fn filename(&self) -> ::std::option::Option<&str> {
        self.filename.as_deref()
    }
    /// <p>The kind of artifact.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::TestGridSessionArtifactType> {
        self.r#type.as_ref()
    }
    /// <p>A semi-stable URL to the content of the object.</p>
    pub fn url(&self) -> ::std::option::Option<&str> {
        self.url.as_deref()
    }
}
impl ::std::fmt::Debug for TestGridSessionArtifact {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("TestGridSessionArtifact");
        formatter.field("filename", &self.filename);
        formatter.field("r#type", &self.r#type);
        formatter.field("url", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl TestGridSessionArtifact {
    /// Creates a new builder-style object to manufacture [`TestGridSessionArtifact`](crate::types::TestGridSessionArtifact).
    pub fn builder() -> crate::types::builders::TestGridSessionArtifactBuilder {
        crate::types::builders::TestGridSessionArtifactBuilder::default()
    }
}

/// A builder for [`TestGridSessionArtifact`](crate::types::TestGridSessionArtifact).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct TestGridSessionArtifactBuilder {
    pub(crate) filename: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::TestGridSessionArtifactType>,
    pub(crate) url: ::std::option::Option<::std::string::String>,
}
impl TestGridSessionArtifactBuilder {
    /// <p>The file name of the artifact.</p>
    pub fn filename(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.filename = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The file name of the artifact.</p>
    pub fn set_filename(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.filename = input;
        self
    }
    /// <p>The file name of the artifact.</p>
    pub fn get_filename(&self) -> &::std::option::Option<::std::string::String> {
        &self.filename
    }
    /// <p>The kind of artifact.</p>
    pub fn r#type(mut self, input: crate::types::TestGridSessionArtifactType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The kind of artifact.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::TestGridSessionArtifactType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The kind of artifact.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::TestGridSessionArtifactType> {
        &self.r#type
    }
    /// <p>A semi-stable URL to the content of the object.</p>
    pub fn url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A semi-stable URL to the content of the object.</p>
    pub fn set_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.url = input;
        self
    }
    /// <p>A semi-stable URL to the content of the object.</p>
    pub fn get_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.url
    }
    /// Consumes the builder and constructs a [`TestGridSessionArtifact`](crate::types::TestGridSessionArtifact).
    pub fn build(self) -> crate::types::TestGridSessionArtifact {
        crate::types::TestGridSessionArtifact {
            filename: self.filename,
            r#type: self.r#type,
            url: self.url,
        }
    }
}
impl ::std::fmt::Debug for TestGridSessionArtifactBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("TestGridSessionArtifactBuilder");
        formatter.field("filename", &self.filename);
        formatter.field("r#type", &self.r#type);
        formatter.field("url", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
