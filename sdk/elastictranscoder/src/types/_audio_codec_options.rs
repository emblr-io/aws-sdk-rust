// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Options associated with your audio codec.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AudioCodecOptions {
    /// <p>You can only choose an audio profile when you specify AAC for the value of Audio:Codec.</p>
    /// <p>Specify the AAC profile for the output file. Elastic Transcoder supports the following profiles:</p>
    /// <ul>
    /// <li>
    /// <p><code>auto</code>: If you specify <code>auto</code>, Elastic Transcoder selects the profile based on the bit rate selected for the output file.</p></li>
    /// <li>
    /// <p><code>AAC-LC</code>: The most common AAC profile. Use for bit rates larger than 64 kbps.</p></li>
    /// <li>
    /// <p><code>HE-AAC</code>: Not supported on some older players and devices. Use for bit rates between 40 and 80 kbps.</p></li>
    /// <li>
    /// <p><code>HE-AACv2</code>: Not supported on some players and devices. Use for bit rates less than 48 kbps.</p></li>
    /// </ul>
    /// <p>All outputs in a <code>Smooth</code> playlist must have the same value for <code>Profile</code>.</p><note>
    /// <p>If you created any presets before AAC profiles were added, Elastic Transcoder automatically updated your presets to use AAC-LC. You can change the value as required.</p>
    /// </note>
    pub profile: ::std::option::Option<::std::string::String>,
    /// <p>You can only choose an audio bit depth when you specify <code>flac</code> or <code>pcm</code> for the value of Audio:Codec.</p>
    /// <p>The bit depth of a sample is how many bits of information are included in the audio samples. The higher the bit depth, the better the audio, but the larger the file.</p>
    /// <p>Valid values are <code>16</code> and <code>24</code>.</p>
    /// <p>The most common bit depth is <code>24</code>.</p>
    pub bit_depth: ::std::option::Option<::std::string::String>,
    /// <p>You can only choose an audio bit order when you specify <code>pcm</code> for the value of Audio:Codec.</p>
    /// <p>The order the bits of a PCM sample are stored in.</p>
    /// <p>The supported value is <code>LittleEndian</code>.</p>
    pub bit_order: ::std::option::Option<::std::string::String>,
    /// <p>You can only choose whether an audio sample is signed when you specify <code>pcm</code> for the value of Audio:Codec.</p>
    /// <p>Whether audio samples are represented with negative and positive numbers (signed) or only positive numbers (unsigned).</p>
    /// <p>The supported value is <code>Signed</code>.</p>
    pub signed: ::std::option::Option<::std::string::String>,
}
impl AudioCodecOptions {
    /// <p>You can only choose an audio profile when you specify AAC for the value of Audio:Codec.</p>
    /// <p>Specify the AAC profile for the output file. Elastic Transcoder supports the following profiles:</p>
    /// <ul>
    /// <li>
    /// <p><code>auto</code>: If you specify <code>auto</code>, Elastic Transcoder selects the profile based on the bit rate selected for the output file.</p></li>
    /// <li>
    /// <p><code>AAC-LC</code>: The most common AAC profile. Use for bit rates larger than 64 kbps.</p></li>
    /// <li>
    /// <p><code>HE-AAC</code>: Not supported on some older players and devices. Use for bit rates between 40 and 80 kbps.</p></li>
    /// <li>
    /// <p><code>HE-AACv2</code>: Not supported on some players and devices. Use for bit rates less than 48 kbps.</p></li>
    /// </ul>
    /// <p>All outputs in a <code>Smooth</code> playlist must have the same value for <code>Profile</code>.</p><note>
    /// <p>If you created any presets before AAC profiles were added, Elastic Transcoder automatically updated your presets to use AAC-LC. You can change the value as required.</p>
    /// </note>
    pub fn profile(&self) -> ::std::option::Option<&str> {
        self.profile.as_deref()
    }
    /// <p>You can only choose an audio bit depth when you specify <code>flac</code> or <code>pcm</code> for the value of Audio:Codec.</p>
    /// <p>The bit depth of a sample is how many bits of information are included in the audio samples. The higher the bit depth, the better the audio, but the larger the file.</p>
    /// <p>Valid values are <code>16</code> and <code>24</code>.</p>
    /// <p>The most common bit depth is <code>24</code>.</p>
    pub fn bit_depth(&self) -> ::std::option::Option<&str> {
        self.bit_depth.as_deref()
    }
    /// <p>You can only choose an audio bit order when you specify <code>pcm</code> for the value of Audio:Codec.</p>
    /// <p>The order the bits of a PCM sample are stored in.</p>
    /// <p>The supported value is <code>LittleEndian</code>.</p>
    pub fn bit_order(&self) -> ::std::option::Option<&str> {
        self.bit_order.as_deref()
    }
    /// <p>You can only choose whether an audio sample is signed when you specify <code>pcm</code> for the value of Audio:Codec.</p>
    /// <p>Whether audio samples are represented with negative and positive numbers (signed) or only positive numbers (unsigned).</p>
    /// <p>The supported value is <code>Signed</code>.</p>
    pub fn signed(&self) -> ::std::option::Option<&str> {
        self.signed.as_deref()
    }
}
impl AudioCodecOptions {
    /// Creates a new builder-style object to manufacture [`AudioCodecOptions`](crate::types::AudioCodecOptions).
    pub fn builder() -> crate::types::builders::AudioCodecOptionsBuilder {
        crate::types::builders::AudioCodecOptionsBuilder::default()
    }
}

/// A builder for [`AudioCodecOptions`](crate::types::AudioCodecOptions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AudioCodecOptionsBuilder {
    pub(crate) profile: ::std::option::Option<::std::string::String>,
    pub(crate) bit_depth: ::std::option::Option<::std::string::String>,
    pub(crate) bit_order: ::std::option::Option<::std::string::String>,
    pub(crate) signed: ::std::option::Option<::std::string::String>,
}
impl AudioCodecOptionsBuilder {
    /// <p>You can only choose an audio profile when you specify AAC for the value of Audio:Codec.</p>
    /// <p>Specify the AAC profile for the output file. Elastic Transcoder supports the following profiles:</p>
    /// <ul>
    /// <li>
    /// <p><code>auto</code>: If you specify <code>auto</code>, Elastic Transcoder selects the profile based on the bit rate selected for the output file.</p></li>
    /// <li>
    /// <p><code>AAC-LC</code>: The most common AAC profile. Use for bit rates larger than 64 kbps.</p></li>
    /// <li>
    /// <p><code>HE-AAC</code>: Not supported on some older players and devices. Use for bit rates between 40 and 80 kbps.</p></li>
    /// <li>
    /// <p><code>HE-AACv2</code>: Not supported on some players and devices. Use for bit rates less than 48 kbps.</p></li>
    /// </ul>
    /// <p>All outputs in a <code>Smooth</code> playlist must have the same value for <code>Profile</code>.</p><note>
    /// <p>If you created any presets before AAC profiles were added, Elastic Transcoder automatically updated your presets to use AAC-LC. You can change the value as required.</p>
    /// </note>
    pub fn profile(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.profile = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>You can only choose an audio profile when you specify AAC for the value of Audio:Codec.</p>
    /// <p>Specify the AAC profile for the output file. Elastic Transcoder supports the following profiles:</p>
    /// <ul>
    /// <li>
    /// <p><code>auto</code>: If you specify <code>auto</code>, Elastic Transcoder selects the profile based on the bit rate selected for the output file.</p></li>
    /// <li>
    /// <p><code>AAC-LC</code>: The most common AAC profile. Use for bit rates larger than 64 kbps.</p></li>
    /// <li>
    /// <p><code>HE-AAC</code>: Not supported on some older players and devices. Use for bit rates between 40 and 80 kbps.</p></li>
    /// <li>
    /// <p><code>HE-AACv2</code>: Not supported on some players and devices. Use for bit rates less than 48 kbps.</p></li>
    /// </ul>
    /// <p>All outputs in a <code>Smooth</code> playlist must have the same value for <code>Profile</code>.</p><note>
    /// <p>If you created any presets before AAC profiles were added, Elastic Transcoder automatically updated your presets to use AAC-LC. You can change the value as required.</p>
    /// </note>
    pub fn set_profile(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.profile = input;
        self
    }
    /// <p>You can only choose an audio profile when you specify AAC for the value of Audio:Codec.</p>
    /// <p>Specify the AAC profile for the output file. Elastic Transcoder supports the following profiles:</p>
    /// <ul>
    /// <li>
    /// <p><code>auto</code>: If you specify <code>auto</code>, Elastic Transcoder selects the profile based on the bit rate selected for the output file.</p></li>
    /// <li>
    /// <p><code>AAC-LC</code>: The most common AAC profile. Use for bit rates larger than 64 kbps.</p></li>
    /// <li>
    /// <p><code>HE-AAC</code>: Not supported on some older players and devices. Use for bit rates between 40 and 80 kbps.</p></li>
    /// <li>
    /// <p><code>HE-AACv2</code>: Not supported on some players and devices. Use for bit rates less than 48 kbps.</p></li>
    /// </ul>
    /// <p>All outputs in a <code>Smooth</code> playlist must have the same value for <code>Profile</code>.</p><note>
    /// <p>If you created any presets before AAC profiles were added, Elastic Transcoder automatically updated your presets to use AAC-LC. You can change the value as required.</p>
    /// </note>
    pub fn get_profile(&self) -> &::std::option::Option<::std::string::String> {
        &self.profile
    }
    /// <p>You can only choose an audio bit depth when you specify <code>flac</code> or <code>pcm</code> for the value of Audio:Codec.</p>
    /// <p>The bit depth of a sample is how many bits of information are included in the audio samples. The higher the bit depth, the better the audio, but the larger the file.</p>
    /// <p>Valid values are <code>16</code> and <code>24</code>.</p>
    /// <p>The most common bit depth is <code>24</code>.</p>
    pub fn bit_depth(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bit_depth = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>You can only choose an audio bit depth when you specify <code>flac</code> or <code>pcm</code> for the value of Audio:Codec.</p>
    /// <p>The bit depth of a sample is how many bits of information are included in the audio samples. The higher the bit depth, the better the audio, but the larger the file.</p>
    /// <p>Valid values are <code>16</code> and <code>24</code>.</p>
    /// <p>The most common bit depth is <code>24</code>.</p>
    pub fn set_bit_depth(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bit_depth = input;
        self
    }
    /// <p>You can only choose an audio bit depth when you specify <code>flac</code> or <code>pcm</code> for the value of Audio:Codec.</p>
    /// <p>The bit depth of a sample is how many bits of information are included in the audio samples. The higher the bit depth, the better the audio, but the larger the file.</p>
    /// <p>Valid values are <code>16</code> and <code>24</code>.</p>
    /// <p>The most common bit depth is <code>24</code>.</p>
    pub fn get_bit_depth(&self) -> &::std::option::Option<::std::string::String> {
        &self.bit_depth
    }
    /// <p>You can only choose an audio bit order when you specify <code>pcm</code> for the value of Audio:Codec.</p>
    /// <p>The order the bits of a PCM sample are stored in.</p>
    /// <p>The supported value is <code>LittleEndian</code>.</p>
    pub fn bit_order(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bit_order = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>You can only choose an audio bit order when you specify <code>pcm</code> for the value of Audio:Codec.</p>
    /// <p>The order the bits of a PCM sample are stored in.</p>
    /// <p>The supported value is <code>LittleEndian</code>.</p>
    pub fn set_bit_order(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bit_order = input;
        self
    }
    /// <p>You can only choose an audio bit order when you specify <code>pcm</code> for the value of Audio:Codec.</p>
    /// <p>The order the bits of a PCM sample are stored in.</p>
    /// <p>The supported value is <code>LittleEndian</code>.</p>
    pub fn get_bit_order(&self) -> &::std::option::Option<::std::string::String> {
        &self.bit_order
    }
    /// <p>You can only choose whether an audio sample is signed when you specify <code>pcm</code> for the value of Audio:Codec.</p>
    /// <p>Whether audio samples are represented with negative and positive numbers (signed) or only positive numbers (unsigned).</p>
    /// <p>The supported value is <code>Signed</code>.</p>
    pub fn signed(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.signed = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>You can only choose whether an audio sample is signed when you specify <code>pcm</code> for the value of Audio:Codec.</p>
    /// <p>Whether audio samples are represented with negative and positive numbers (signed) or only positive numbers (unsigned).</p>
    /// <p>The supported value is <code>Signed</code>.</p>
    pub fn set_signed(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.signed = input;
        self
    }
    /// <p>You can only choose whether an audio sample is signed when you specify <code>pcm</code> for the value of Audio:Codec.</p>
    /// <p>Whether audio samples are represented with negative and positive numbers (signed) or only positive numbers (unsigned).</p>
    /// <p>The supported value is <code>Signed</code>.</p>
    pub fn get_signed(&self) -> &::std::option::Option<::std::string::String> {
        &self.signed
    }
    /// Consumes the builder and constructs a [`AudioCodecOptions`](crate::types::AudioCodecOptions).
    pub fn build(self) -> crate::types::AudioCodecOptions {
        crate::types::AudioCodecOptions {
            profile: self.profile,
            bit_depth: self.bit_depth,
            bit_order: self.bit_order,
            signed: self.signed,
        }
    }
}
