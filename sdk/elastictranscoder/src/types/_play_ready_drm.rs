// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The PlayReady DRM settings, if any, that you want Elastic Transcoder to apply to the output files associated with this playlist.</p>
/// <p>PlayReady DRM encrypts your media files using <code>aes-ctr</code> encryption.</p>
/// <p>If you use DRM for an <code>HLSv3</code> playlist, your outputs must have a master playlist.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PlayReadyDrm {
    /// <p>The type of DRM, if any, that you want Elastic Transcoder to apply to the output files associated with this playlist.</p>
    pub format: ::std::option::Option<::std::string::String>,
    /// <p>The DRM key for your file, provided by your DRM license provider. The key must be base64-encoded, and it must be one of the following bit lengths before being base64-encoded:</p>
    /// <p><code>128</code>, <code>192</code>, or <code>256</code>.</p>
    /// <p>The key must also be encrypted by using AWS KMS.</p>
    pub key: ::std::option::Option<::std::string::String>,
    /// <p>The MD5 digest of the key used for DRM on your file, and that you want Elastic Transcoder to use as a checksum to make sure your key was not corrupted in transit. The key MD5 must be base64-encoded, and it must be exactly 16 bytes before being base64-encoded.</p>
    pub key_md5: ::std::option::Option<::std::string::String>,
    /// <p>The ID for your DRM key, so that your DRM license provider knows which key to provide.</p>
    /// <p>The key ID must be provided in big endian, and Elastic Transcoder converts it to little endian before inserting it into the PlayReady DRM headers. If you are unsure whether your license server provides your key ID in big or little endian, check with your DRM provider.</p>
    pub key_id: ::std::option::Option<::std::string::String>,
    /// <p>The series of random bits created by a random bit generator, unique for every encryption operation, that you want Elastic Transcoder to use to encrypt your files. The initialization vector must be base64-encoded, and it must be exactly 8 bytes long before being base64-encoded. If no initialization vector is provided, Elastic Transcoder generates one for you.</p>
    pub initialization_vector: ::std::option::Option<::std::string::String>,
    /// <p>The location of the license key required to play DRM content. The URL must be an absolute path, and is referenced by the PlayReady header. The PlayReady header is referenced in the protection header of the client manifest for Smooth Streaming outputs, and in the EXT-X-DXDRM and EXT-XDXDRMINFO metadata tags for HLS playlist outputs. An example URL looks like this: <code>https://www.example.com/exampleKey/</code></p>
    pub license_acquisition_url: ::std::option::Option<::std::string::String>,
}
impl PlayReadyDrm {
    /// <p>The type of DRM, if any, that you want Elastic Transcoder to apply to the output files associated with this playlist.</p>
    pub fn format(&self) -> ::std::option::Option<&str> {
        self.format.as_deref()
    }
    /// <p>The DRM key for your file, provided by your DRM license provider. The key must be base64-encoded, and it must be one of the following bit lengths before being base64-encoded:</p>
    /// <p><code>128</code>, <code>192</code>, or <code>256</code>.</p>
    /// <p>The key must also be encrypted by using AWS KMS.</p>
    pub fn key(&self) -> ::std::option::Option<&str> {
        self.key.as_deref()
    }
    /// <p>The MD5 digest of the key used for DRM on your file, and that you want Elastic Transcoder to use as a checksum to make sure your key was not corrupted in transit. The key MD5 must be base64-encoded, and it must be exactly 16 bytes before being base64-encoded.</p>
    pub fn key_md5(&self) -> ::std::option::Option<&str> {
        self.key_md5.as_deref()
    }
    /// <p>The ID for your DRM key, so that your DRM license provider knows which key to provide.</p>
    /// <p>The key ID must be provided in big endian, and Elastic Transcoder converts it to little endian before inserting it into the PlayReady DRM headers. If you are unsure whether your license server provides your key ID in big or little endian, check with your DRM provider.</p>
    pub fn key_id(&self) -> ::std::option::Option<&str> {
        self.key_id.as_deref()
    }
    /// <p>The series of random bits created by a random bit generator, unique for every encryption operation, that you want Elastic Transcoder to use to encrypt your files. The initialization vector must be base64-encoded, and it must be exactly 8 bytes long before being base64-encoded. If no initialization vector is provided, Elastic Transcoder generates one for you.</p>
    pub fn initialization_vector(&self) -> ::std::option::Option<&str> {
        self.initialization_vector.as_deref()
    }
    /// <p>The location of the license key required to play DRM content. The URL must be an absolute path, and is referenced by the PlayReady header. The PlayReady header is referenced in the protection header of the client manifest for Smooth Streaming outputs, and in the EXT-X-DXDRM and EXT-XDXDRMINFO metadata tags for HLS playlist outputs. An example URL looks like this: <code>https://www.example.com/exampleKey/</code></p>
    pub fn license_acquisition_url(&self) -> ::std::option::Option<&str> {
        self.license_acquisition_url.as_deref()
    }
}
impl PlayReadyDrm {
    /// Creates a new builder-style object to manufacture [`PlayReadyDrm`](crate::types::PlayReadyDrm).
    pub fn builder() -> crate::types::builders::PlayReadyDrmBuilder {
        crate::types::builders::PlayReadyDrmBuilder::default()
    }
}

/// A builder for [`PlayReadyDrm`](crate::types::PlayReadyDrm).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PlayReadyDrmBuilder {
    pub(crate) format: ::std::option::Option<::std::string::String>,
    pub(crate) key: ::std::option::Option<::std::string::String>,
    pub(crate) key_md5: ::std::option::Option<::std::string::String>,
    pub(crate) key_id: ::std::option::Option<::std::string::String>,
    pub(crate) initialization_vector: ::std::option::Option<::std::string::String>,
    pub(crate) license_acquisition_url: ::std::option::Option<::std::string::String>,
}
impl PlayReadyDrmBuilder {
    /// <p>The type of DRM, if any, that you want Elastic Transcoder to apply to the output files associated with this playlist.</p>
    pub fn format(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.format = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of DRM, if any, that you want Elastic Transcoder to apply to the output files associated with this playlist.</p>
    pub fn set_format(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.format = input;
        self
    }
    /// <p>The type of DRM, if any, that you want Elastic Transcoder to apply to the output files associated with this playlist.</p>
    pub fn get_format(&self) -> &::std::option::Option<::std::string::String> {
        &self.format
    }
    /// <p>The DRM key for your file, provided by your DRM license provider. The key must be base64-encoded, and it must be one of the following bit lengths before being base64-encoded:</p>
    /// <p><code>128</code>, <code>192</code>, or <code>256</code>.</p>
    /// <p>The key must also be encrypted by using AWS KMS.</p>
    pub fn key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The DRM key for your file, provided by your DRM license provider. The key must be base64-encoded, and it must be one of the following bit lengths before being base64-encoded:</p>
    /// <p><code>128</code>, <code>192</code>, or <code>256</code>.</p>
    /// <p>The key must also be encrypted by using AWS KMS.</p>
    pub fn set_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key = input;
        self
    }
    /// <p>The DRM key for your file, provided by your DRM license provider. The key must be base64-encoded, and it must be one of the following bit lengths before being base64-encoded:</p>
    /// <p><code>128</code>, <code>192</code>, or <code>256</code>.</p>
    /// <p>The key must also be encrypted by using AWS KMS.</p>
    pub fn get_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.key
    }
    /// <p>The MD5 digest of the key used for DRM on your file, and that you want Elastic Transcoder to use as a checksum to make sure your key was not corrupted in transit. The key MD5 must be base64-encoded, and it must be exactly 16 bytes before being base64-encoded.</p>
    pub fn key_md5(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key_md5 = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The MD5 digest of the key used for DRM on your file, and that you want Elastic Transcoder to use as a checksum to make sure your key was not corrupted in transit. The key MD5 must be base64-encoded, and it must be exactly 16 bytes before being base64-encoded.</p>
    pub fn set_key_md5(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key_md5 = input;
        self
    }
    /// <p>The MD5 digest of the key used for DRM on your file, and that you want Elastic Transcoder to use as a checksum to make sure your key was not corrupted in transit. The key MD5 must be base64-encoded, and it must be exactly 16 bytes before being base64-encoded.</p>
    pub fn get_key_md5(&self) -> &::std::option::Option<::std::string::String> {
        &self.key_md5
    }
    /// <p>The ID for your DRM key, so that your DRM license provider knows which key to provide.</p>
    /// <p>The key ID must be provided in big endian, and Elastic Transcoder converts it to little endian before inserting it into the PlayReady DRM headers. If you are unsure whether your license server provides your key ID in big or little endian, check with your DRM provider.</p>
    pub fn key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID for your DRM key, so that your DRM license provider knows which key to provide.</p>
    /// <p>The key ID must be provided in big endian, and Elastic Transcoder converts it to little endian before inserting it into the PlayReady DRM headers. If you are unsure whether your license server provides your key ID in big or little endian, check with your DRM provider.</p>
    pub fn set_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key_id = input;
        self
    }
    /// <p>The ID for your DRM key, so that your DRM license provider knows which key to provide.</p>
    /// <p>The key ID must be provided in big endian, and Elastic Transcoder converts it to little endian before inserting it into the PlayReady DRM headers. If you are unsure whether your license server provides your key ID in big or little endian, check with your DRM provider.</p>
    pub fn get_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.key_id
    }
    /// <p>The series of random bits created by a random bit generator, unique for every encryption operation, that you want Elastic Transcoder to use to encrypt your files. The initialization vector must be base64-encoded, and it must be exactly 8 bytes long before being base64-encoded. If no initialization vector is provided, Elastic Transcoder generates one for you.</p>
    pub fn initialization_vector(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.initialization_vector = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The series of random bits created by a random bit generator, unique for every encryption operation, that you want Elastic Transcoder to use to encrypt your files. The initialization vector must be base64-encoded, and it must be exactly 8 bytes long before being base64-encoded. If no initialization vector is provided, Elastic Transcoder generates one for you.</p>
    pub fn set_initialization_vector(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.initialization_vector = input;
        self
    }
    /// <p>The series of random bits created by a random bit generator, unique for every encryption operation, that you want Elastic Transcoder to use to encrypt your files. The initialization vector must be base64-encoded, and it must be exactly 8 bytes long before being base64-encoded. If no initialization vector is provided, Elastic Transcoder generates one for you.</p>
    pub fn get_initialization_vector(&self) -> &::std::option::Option<::std::string::String> {
        &self.initialization_vector
    }
    /// <p>The location of the license key required to play DRM content. The URL must be an absolute path, and is referenced by the PlayReady header. The PlayReady header is referenced in the protection header of the client manifest for Smooth Streaming outputs, and in the EXT-X-DXDRM and EXT-XDXDRMINFO metadata tags for HLS playlist outputs. An example URL looks like this: <code>https://www.example.com/exampleKey/</code></p>
    pub fn license_acquisition_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.license_acquisition_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The location of the license key required to play DRM content. The URL must be an absolute path, and is referenced by the PlayReady header. The PlayReady header is referenced in the protection header of the client manifest for Smooth Streaming outputs, and in the EXT-X-DXDRM and EXT-XDXDRMINFO metadata tags for HLS playlist outputs. An example URL looks like this: <code>https://www.example.com/exampleKey/</code></p>
    pub fn set_license_acquisition_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.license_acquisition_url = input;
        self
    }
    /// <p>The location of the license key required to play DRM content. The URL must be an absolute path, and is referenced by the PlayReady header. The PlayReady header is referenced in the protection header of the client manifest for Smooth Streaming outputs, and in the EXT-X-DXDRM and EXT-XDXDRMINFO metadata tags for HLS playlist outputs. An example URL looks like this: <code>https://www.example.com/exampleKey/</code></p>
    pub fn get_license_acquisition_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.license_acquisition_url
    }
    /// Consumes the builder and constructs a [`PlayReadyDrm`](crate::types::PlayReadyDrm).
    pub fn build(self) -> crate::types::PlayReadyDrm {
        crate::types::PlayReadyDrm {
            format: self.format,
            key: self.key,
            key_md5: self.key_md5,
            key_id: self.key_id,
            initialization_vector: self.initialization_vector,
            license_acquisition_url: self.license_acquisition_url,
        }
    }
}
