// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutImageInput {
    /// <p>The Amazon Web Services account ID, or registry alias, that's associated with the public registry that contains the repository where the image is put. If you do not specify a registry, the default public registry is assumed.</p>
    pub registry_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the repository where the image is put.</p>
    pub repository_name: ::std::option::Option<::std::string::String>,
    /// <p>The image manifest that corresponds to the image to be uploaded.</p>
    pub image_manifest: ::std::option::Option<::std::string::String>,
    /// <p>The media type of the image manifest. If you push an image manifest that doesn't contain the <code>mediaType</code> field, you must specify the <code>imageManifestMediaType</code> in the request.</p>
    pub image_manifest_media_type: ::std::option::Option<::std::string::String>,
    /// <p>The tag to associate with the image. This parameter is required for images that use the Docker Image Manifest V2 Schema 2 or Open Container Initiative (OCI) formats.</p>
    pub image_tag: ::std::option::Option<::std::string::String>,
    /// <p>The image digest of the image manifest that corresponds to the image.</p>
    pub image_digest: ::std::option::Option<::std::string::String>,
}
impl PutImageInput {
    /// <p>The Amazon Web Services account ID, or registry alias, that's associated with the public registry that contains the repository where the image is put. If you do not specify a registry, the default public registry is assumed.</p>
    pub fn registry_id(&self) -> ::std::option::Option<&str> {
        self.registry_id.as_deref()
    }
    /// <p>The name of the repository where the image is put.</p>
    pub fn repository_name(&self) -> ::std::option::Option<&str> {
        self.repository_name.as_deref()
    }
    /// <p>The image manifest that corresponds to the image to be uploaded.</p>
    pub fn image_manifest(&self) -> ::std::option::Option<&str> {
        self.image_manifest.as_deref()
    }
    /// <p>The media type of the image manifest. If you push an image manifest that doesn't contain the <code>mediaType</code> field, you must specify the <code>imageManifestMediaType</code> in the request.</p>
    pub fn image_manifest_media_type(&self) -> ::std::option::Option<&str> {
        self.image_manifest_media_type.as_deref()
    }
    /// <p>The tag to associate with the image. This parameter is required for images that use the Docker Image Manifest V2 Schema 2 or Open Container Initiative (OCI) formats.</p>
    pub fn image_tag(&self) -> ::std::option::Option<&str> {
        self.image_tag.as_deref()
    }
    /// <p>The image digest of the image manifest that corresponds to the image.</p>
    pub fn image_digest(&self) -> ::std::option::Option<&str> {
        self.image_digest.as_deref()
    }
}
impl PutImageInput {
    /// Creates a new builder-style object to manufacture [`PutImageInput`](crate::operation::put_image::PutImageInput).
    pub fn builder() -> crate::operation::put_image::builders::PutImageInputBuilder {
        crate::operation::put_image::builders::PutImageInputBuilder::default()
    }
}

/// A builder for [`PutImageInput`](crate::operation::put_image::PutImageInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutImageInputBuilder {
    pub(crate) registry_id: ::std::option::Option<::std::string::String>,
    pub(crate) repository_name: ::std::option::Option<::std::string::String>,
    pub(crate) image_manifest: ::std::option::Option<::std::string::String>,
    pub(crate) image_manifest_media_type: ::std::option::Option<::std::string::String>,
    pub(crate) image_tag: ::std::option::Option<::std::string::String>,
    pub(crate) image_digest: ::std::option::Option<::std::string::String>,
}
impl PutImageInputBuilder {
    /// <p>The Amazon Web Services account ID, or registry alias, that's associated with the public registry that contains the repository where the image is put. If you do not specify a registry, the default public registry is assumed.</p>
    pub fn registry_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.registry_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID, or registry alias, that's associated with the public registry that contains the repository where the image is put. If you do not specify a registry, the default public registry is assumed.</p>
    pub fn set_registry_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.registry_id = input;
        self
    }
    /// <p>The Amazon Web Services account ID, or registry alias, that's associated with the public registry that contains the repository where the image is put. If you do not specify a registry, the default public registry is assumed.</p>
    pub fn get_registry_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.registry_id
    }
    /// <p>The name of the repository where the image is put.</p>
    /// This field is required.
    pub fn repository_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.repository_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the repository where the image is put.</p>
    pub fn set_repository_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.repository_name = input;
        self
    }
    /// <p>The name of the repository where the image is put.</p>
    pub fn get_repository_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.repository_name
    }
    /// <p>The image manifest that corresponds to the image to be uploaded.</p>
    /// This field is required.
    pub fn image_manifest(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image_manifest = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The image manifest that corresponds to the image to be uploaded.</p>
    pub fn set_image_manifest(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image_manifest = input;
        self
    }
    /// <p>The image manifest that corresponds to the image to be uploaded.</p>
    pub fn get_image_manifest(&self) -> &::std::option::Option<::std::string::String> {
        &self.image_manifest
    }
    /// <p>The media type of the image manifest. If you push an image manifest that doesn't contain the <code>mediaType</code> field, you must specify the <code>imageManifestMediaType</code> in the request.</p>
    pub fn image_manifest_media_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image_manifest_media_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The media type of the image manifest. If you push an image manifest that doesn't contain the <code>mediaType</code> field, you must specify the <code>imageManifestMediaType</code> in the request.</p>
    pub fn set_image_manifest_media_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image_manifest_media_type = input;
        self
    }
    /// <p>The media type of the image manifest. If you push an image manifest that doesn't contain the <code>mediaType</code> field, you must specify the <code>imageManifestMediaType</code> in the request.</p>
    pub fn get_image_manifest_media_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.image_manifest_media_type
    }
    /// <p>The tag to associate with the image. This parameter is required for images that use the Docker Image Manifest V2 Schema 2 or Open Container Initiative (OCI) formats.</p>
    pub fn image_tag(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image_tag = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The tag to associate with the image. This parameter is required for images that use the Docker Image Manifest V2 Schema 2 or Open Container Initiative (OCI) formats.</p>
    pub fn set_image_tag(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image_tag = input;
        self
    }
    /// <p>The tag to associate with the image. This parameter is required for images that use the Docker Image Manifest V2 Schema 2 or Open Container Initiative (OCI) formats.</p>
    pub fn get_image_tag(&self) -> &::std::option::Option<::std::string::String> {
        &self.image_tag
    }
    /// <p>The image digest of the image manifest that corresponds to the image.</p>
    pub fn image_digest(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image_digest = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The image digest of the image manifest that corresponds to the image.</p>
    pub fn set_image_digest(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image_digest = input;
        self
    }
    /// <p>The image digest of the image manifest that corresponds to the image.</p>
    pub fn get_image_digest(&self) -> &::std::option::Option<::std::string::String> {
        &self.image_digest
    }
    /// Consumes the builder and constructs a [`PutImageInput`](crate::operation::put_image::PutImageInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::put_image::PutImageInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::put_image::PutImageInput {
            registry_id: self.registry_id,
            repository_name: self.repository_name,
            image_manifest: self.image_manifest,
            image_manifest_media_type: self.image_manifest_media_type,
            image_tag: self.image_tag,
            image_digest: self.image_digest,
        })
    }
}
