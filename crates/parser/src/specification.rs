use crate::error::ParseError;

#[derive(Debug, PartialEq)]
enum DirectiveCategory {
    Document,   // https://www.w3.org/TR/CSP3/#directives-document
    Fetch,       // https://www.w3.org/TR/CSP3/#directives-fetch
    Navigation, // https://www.w3.org/TR/CSP3/#directives-navigation
    Other,       // https://www.w3.org/TR/CSP3/#directives-other
    Reporting,  // https://www.w3.org/TR/CSP3/#directives-reporting
}

/// Information about a CSP directive
#[derive(Debug)]
pub struct DirectiveInfo {
    pub name: &'static str,
    pub category: DirectiveCategory,
    pub description: &'static str,
    pub link: &'static str,
}

/// Valid CSP Level 3 directives with metadata

// Fetch directives (§ 6.1)
static DEFAULT_SRC: DirectiveInfo = DirectiveInfo {
    name: "default-src",
    category: DirectiveCategory::Fetch,
    description: "The default-src directive serves as a fallback for the other fetch directives.",
    link: "https://www.w3.org/TR/CSP3/#directive-default-src"
};

static CHILD_SRC: DirectiveInfo = DirectiveInfo {
    name: "child-src",
    category: DirectiveCategory::Fetch,
    description: "The child-src directive restricts the URLs which can be loaded using elements which load resources as part of a browsing context or a worker.",
    link: "https://www.w3.org/TR/CSP3/#directive-child-src"
};

static CONNECT_SRC: DirectiveInfo = DirectiveInfo {
    name: "connect-src",
    category: DirectiveCategory::Fetch,
    description: "The connect-src directive restricts the URLs which can be loaded using script interfaces.",
    link: "https://www.w3.org/TR/CSP3/#directive-connect-src"
};

static FONT_SRC: DirectiveInfo = DirectiveInfo {
    name: "font-src",
    category: DirectiveCategory::Fetch,
    description: "The font-src directive restricts the URLs from which font resources may be loaded.",
    link: "https://www.w3.org/TR/CSP3/#directive-font-src"
};

static FRAME_SRC: DirectiveInfo = DirectiveInfo {
    name: "frame-src",
    category: DirectiveCategory::Fetch,
    description: "The frame-src directive restricts the URLs which may be loaded into child navigables.",
    link: "https://www.w3.org/TR/CSP3/#directive-frame-src"
};

static IMG_SRC: DirectiveInfo = DirectiveInfo {
    name: "img-src",
    category: DirectiveCategory::Fetch,
    description: "The img-src directive restricts the URLs from which image resources may be loaded.",
    link: "https://www.w3.org/TR/CSP3/#directive-img-src"
};

static MANIFEST_SRC: DirectiveInfo = DirectiveInfo {
    name: "manifest-src",
    category: DirectiveCategory::Fetch,
    description: "The manifest-src directive restricts the URLs from which application manifests may be loaded.",
    link: "https://www.w3.org/TR/CSP3/#directive-manifest-src"
};

static MEDIA_SRC: DirectiveInfo = DirectiveInfo {
    name: "media-src",
    category: DirectiveCategory::Fetch,
    description: "The media-src directive restricts the URLs from which video, audio, and associated text track resources may be loaded.",
    link: "https://www.w3.org/TR/CSP3/#directive-media-src"
};

static OBJECT_SRC: DirectiveInfo = DirectiveInfo {
    name: "object-src",
    category: DirectiveCategory::Fetch,
    description: "The object-src directive restricts the URLs from which plugin content may be loaded.",
    link: "https://www.w3.org/TR/CSP3/#directive-object-src"
};

static SCRIPT_SRC: DirectiveInfo = DirectiveInfo {
    name: "script-src",
    category: DirectiveCategory::Fetch,
    description: "The script-src directive restricts the URLs from which scripts may be executed.",
    link: "https://www.w3.org/TR/CSP3/#directive-script-src"
};

static SCRIPT_SRC_ELEM: DirectiveInfo = DirectiveInfo {
    name: "script-src-elem",
    category: DirectiveCategory::Fetch,
    description: "The script-src-elem directive restricts the URLs from which scripts may be executed from script elements.",
    link: "https://www.w3.org/TR/CSP3/#directive-script-src-elem"
};

static SCRIPT_SRC_ATTR: DirectiveInfo = DirectiveInfo {
    name: "script-src-attr",
    category: DirectiveCategory::Fetch,
    description: "The script-src-attr directive restricts the URLs from which scripts in script attributes may be executed.",
    link: "https://www.w3.org/TR/CSP3/#directive-script-src-attr"
};

static STYLE_SRC: DirectiveInfo = DirectiveInfo {
    name: "style-src",
    category: DirectiveCategory::Fetch,
    description: "The style-src directive restricts the URLs from which style may be applied to a document.",
    link: "https://www.w3.org/TR/CSP3/#directive-style-src"
};

static STYLE_SRC_ELEM: DirectiveInfo = DirectiveInfo {
    name: "style-src-elem",
    category: DirectiveCategory::Fetch,
    description: "The style-src-elem directive restricts the URLs from which styles may be applied from style elements.",
    link: "https://www.w3.org/TR/CSP3/#directive-style-src-elem"
};

static STYLE_SRC_ATTR: DirectiveInfo = DirectiveInfo {
    name: "style-src-attr",
    category: DirectiveCategory::Fetch,
    description: "The style-src-attr directive restricts the URLs from which styles may be applied from style attributes.",
    link: "https://www.w3.org/TR/CSP3/#directive-style-src-attr"
};

static WORKER_SRC: DirectiveInfo = DirectiveInfo {
    name: "worker-src",
    category: DirectiveCategory::Fetch,
    description: "The worker-src directive restricts the URLs which may be loaded as workers, shared workers, or service workers.",
    link: "https://www.w3.org/TR/CSP3/#directive-worker-src"
};


// Document directives (§ 6.3)
static BASE_URI: DirectiveInfo = DirectiveInfo {
    name: "base-uri",
    category: DirectiveCategory::Document,
    description: "The base-uri directive restricts the URLs which can be used in a document's base element.",
    link: "https://www.w3.org/TR/CSP3/#directive-base-uri"
};

static SANDBOX: DirectiveInfo = DirectiveInfo {
    name: "sandbox",
    category: DirectiveCategory::Document,
    description: "The sandbox directive restricts a page's actions including preventing popups, preventing the execution of plugins and scripts, and enforcing a same-origin policy.",
    link: "https://www.w3.org/TR/CSP3/#directive-sandbox"
};


// Navigation directives (§ 6.4)
static FORM_ACTION: DirectiveInfo = DirectiveInfo {
    name: "form-action",
    category: DirectiveCategory::Navigation,
    description: "The form-action directive restricts the URLs which can be used as the target of form submissions from a given context.",
    link: "https://www.w3.org/TR/CSP3/#directive-form-action"
};

static FRAME_ANCESTORS: DirectiveInfo = DirectiveInfo {
    name: "frame-ancestors",
    category: DirectiveCategory::Navigation,
    description: "The frame-ancestors directive restricts the URLs that can embed the resource using frame, iframe, object, embed, or applet.",
    link: "https://www.w3.org/TR/CSP3/#directive-frame-ancestors"
};

static NAVIGATE_TO: DirectiveInfo = DirectiveInfo {
    name: "navigate-to",
    category: DirectiveCategory::Navigation,
    description: "The navigate-to directive restricts the URLs to which a document can initiate navigations.",
    link: "https://www.w3.org/TR/CSP3/#directive-navigate-to"
};

// Reporting directives (§ 6.5)
static REPORT_URI: DirectiveInfo = DirectiveInfo {
    name: "report-uri",
    category: DirectiveCategory::Reporting,
    description: "The report-uri directive defines a set of endpoints to which CSP violation reports will be sent when particular behaviors are prevented. This directive is deprecated in favor of report-to.",
    link: "https://www.w3.org/TR/CSP3/#directive-report-uri"
};

static REPORT_TO: DirectiveInfo = DirectiveInfo {
    name: "report-to",
    category: DirectiveCategory::Reporting,
    description: "The report-to directive defines a reporting endpoint to which violation reports ought to be sent.",
    link: "https://www.w3.org/TR/CSP3/#directive-report-to"
};


// Other directives (§ 6.6)
static BLOCK_ALL_MIXED_CONTENT: DirectiveInfo = DirectiveInfo {
    name: "block-all-mixed-content",
    category: DirectiveCategory::Other,
    description: "The block-all-mixed-content directive prevents loading any assets using HTTP when the page is loaded using HTTPS.",
    link: "https://www.w3.org/TR/mixed-content/#strict-checking"
};

static UPGRADE_INSECURE_REQUESTS: DirectiveInfo = DirectiveInfo {
    name: "upgrade-insecure-requests",
    category: DirectiveCategory::Other,
    description: "The upgrade-insecure-requests directive instructs user agents to treat all of a site's insecure URLs as though they have been replaced with secure URLs.",
    link: "https://www.w3.org/TR/upgrade-insecure-requests/#delivery"
};


/// Looks up metadata for a CSP directive by name
impl DirectiveInfo {
    pub fn lookup(name: &str) -> Option<&'static DirectiveInfo> {
        match name {
            // Fetch directives
            "default-src" => Some(&DEFAULT_SRC),
            "child-src" => Some(&CHILD_SRC),
            "connect-src" => Some(&CONNECT_SRC),
            "font-src" => Some(&FONT_SRC),
            "frame-src" => Some(&FRAME_SRC),
            "img-src" => Some(&IMG_SRC),
            "manifest-src" => Some(&MANIFEST_SRC),
            "media-src" => Some(&MEDIA_SRC),
            "object-src" => Some(&OBJECT_SRC),
            "script-src" => Some(&SCRIPT_SRC),
            "script-src-elem" => Some(&SCRIPT_SRC_ELEM),
            "script-src-attr" => Some(&SCRIPT_SRC_ATTR),
            "style-src" => Some(&STYLE_SRC),
            "style-src-elem" => Some(&STYLE_SRC_ELEM),
            "style-src-attr" => Some(&STYLE_SRC_ATTR),
            "worker-src" => Some(&WORKER_SRC),
            
            // Document directives
            "base-uri" => Some(&BASE_URI),
            "sandbox" => Some(&SANDBOX),
            
            // Navigation directives
            "form-action" => Some(&FORM_ACTION),
            "frame-ancestors" => Some(&FRAME_ANCESTORS),
            "navigate-to" => Some(&NAVIGATE_TO),
            
            // Reporting directives
            "report-uri" => Some(&REPORT_URI),
            "report-to" => Some(&REPORT_TO),
            
            // Other directives
            "block-all-mixed-content" => Some(&BLOCK_ALL_MIXED_CONTENT),
            "upgrade-insecure-requests" => Some(&UPGRADE_INSECURE_REQUESTS),
            
            // Unknown directive
            _ => None,
        }
    }

    pub fn is_fetch(&self) -> bool {
        self.category == DirectiveCategory::Fetch
    }

    pub fn is_document(&self) -> bool {
        self.category == DirectiveCategory::Document
    }
    
    pub fn is_navigation(&self) -> bool {
        self.category == DirectiveCategory::Navigation
    }

    pub fn is_reporting(&self) -> bool {
        self.category == DirectiveCategory::Reporting
    }
    
    pub fn is_other(&self) -> bool {
        self.category == DirectiveCategory::Other
    }
}
