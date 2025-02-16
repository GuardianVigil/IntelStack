import React from 'react';
import {
    Card,
    Badge,
    Table,
    Alert,
    ProgressBar,
    Accordion,
    Row,
    Col
} from 'react-bootstrap';

const ThreatBadge = ({ score }) => {
    const getVariant = (score) => {
        if (score >= 70) return 'danger';
        if (score >= 40) return 'warning';
        return 'success';
    };

    return (
        <Badge bg={getVariant(score)} className="fs-5 mb-2">
            Threat Score: {score}
        </Badge>
    );
};

const ConfidenceBadge = ({ score }) => {
    const getVariant = (score) => {
        if (score >= 70) return 'success';
        if (score >= 40) return 'warning';
        return 'danger';
    };

    return (
        <Badge bg={getVariant(score)} className="fs-5 mb-2 ms-2">
            Confidence: {score}%
        </Badge>
    );
};

const AuthenticationResults = ({ auth }) => {
    const getStatusBadge = (status) => {
        const variants = {
            success: 'success',
            danger: 'danger',
            warning: 'warning',
            secondary: 'secondary'
        };
        return <Badge bg={variants[status]}>{status.toUpperCase()}</Badge>;
    };

    return (
        <Card className="mb-4">
            <Card.Header>
                <h5 className="card-title mb-0">Authentication Results</h5>
            </Card.Header>
            <Card.Body>
                <Table responsive>
                    <thead>
                        <tr>
                            <th>Check</th>
                            <th>Result</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>SPF</td>
                            <td>{auth.spf.result}</td>
                            <td>{getStatusBadge(auth.spf.status)}</td>
                        </tr>
                        <tr>
                            <td>DKIM</td>
                            <td>{auth.dkim.result}</td>
                            <td>{getStatusBadge(auth.dkim.status)}</td>
                        </tr>
                        <tr>
                            <td>DMARC</td>
                            <td>{auth.dmarc.result}</td>
                            <td>{getStatusBadge(auth.dmarc.status)}</td>
                        </tr>
                    </tbody>
                </Table>
            </Card.Body>
        </Card>
    );
};

const IPAnalysis = ({ ipAnalysis }) => {
    return (
        <Card className="mb-4">
            <Card.Header>
                <h5 className="card-title mb-0">IP Analysis</h5>
            </Card.Header>
            <Card.Body>
                <Accordion>
                    {Object.entries(ipAnalysis).map(([ip, data], index) => (
                        <Accordion.Item eventKey={index} key={ip}>
                            <Accordion.Header>
                                {ip} {' '}
                                {data.is_malicious && 
                                    <Badge bg="danger" className="ms-2">Malicious</Badge>
                                }
                            </Accordion.Header>
                            <Accordion.Body>
                                <Row>
                                    <Col md={6}>
                                        <h6>Geolocation</h6>
                                        {data.geolocation ? (
                                            <p>
                                                {data.geolocation.country}, {data.geolocation.city}
                                            </p>
                                        ) : (
                                            <p>No geolocation data available</p>
                                        )}
                                    </Col>
                                    <Col md={6}>
                                        <h6>Reputation</h6>
                                        {data.reputation ? (
                                            <ProgressBar 
                                                now={data.reputation} 
                                                variant={data.reputation > 50 ? 'success' : 'danger'}
                                            />
                                        ) : (
                                            <p>No reputation data available</p>
                                        )}
                                    </Col>
                                </Row>
                                <h6 className="mt-3">Platform Analysis</h6>
                                <Accordion>
                                    {Object.entries(data.analysis).map(([platform, analysis], pIndex) => (
                                        <Accordion.Item eventKey={pIndex} key={platform}>
                                            <Accordion.Header>
                                                {platform.toUpperCase()}
                                            </Accordion.Header>
                                            <Accordion.Body>
                                                <pre className="bg-light p-3 rounded">
                                                    {JSON.stringify(analysis, null, 2)}
                                                </pre>
                                            </Accordion.Body>
                                        </Accordion.Item>
                                    ))}
                                </Accordion>
                            </Accordion.Body>
                        </Accordion.Item>
                    ))}
                </Accordion>
            </Card.Body>
        </Card>
    );
};

const URLAnalysis = ({ urlAnalysis }) => {
    return (
        <Card className="mb-4">
            <Card.Header>
                <h5 className="card-title mb-0">URL Analysis</h5>
            </Card.Header>
            <Card.Body>
                <Table responsive>
                    <thead>
                        <tr>
                            <th>URL</th>
                            <th>Status</th>
                            <th>Reputation</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        {urlAnalysis.map((url, index) => (
                            <tr key={index}>
                                <td>{url.url}</td>
                                <td>
                                    <Badge bg={url.is_malicious ? 'danger' : 'success'}>
                                        {url.status}
                                    </Badge>
                                </td>
                                <td>
                                    {url.reputation && (
                                        <ProgressBar 
                                            now={url.reputation} 
                                            variant={url.reputation > 50 ? 'success' : 'danger'}
                                            style={{ width: '100px' }}
                                        />
                                    )}
                                </td>
                                <td>
                                    <Accordion>
                                        <Accordion.Item eventKey="0">
                                            <Accordion.Header>View Details</Accordion.Header>
                                            <Accordion.Body>
                                                <pre className="bg-light p-3 rounded">
                                                    {JSON.stringify(url.analysis, null, 2)}
                                                </pre>
                                            </Accordion.Body>
                                        </Accordion.Item>
                                    </Accordion>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </Table>
            </Card.Body>
        </Card>
    );
};

const AttachmentAnalysis = ({ attachmentAnalysis }) => {
    return (
        <Card className="mb-4">
            <Card.Header>
                <h5 className="card-title mb-0">Attachment Analysis</h5>
            </Card.Header>
            <Card.Body>
                {attachmentAnalysis.length === 0 ? (
                    <Alert variant="info">No attachments found</Alert>
                ) : (
                    <Accordion>
                        {attachmentAnalysis.map((attachment, index) => (
                            <Accordion.Item eventKey={index} key={index}>
                                <Accordion.Header>
                                    {attachment.filename} {' '}
                                    {attachment.is_malicious && 
                                        <Badge bg="danger" className="ms-2">Malicious</Badge>
                                    }
                                </Accordion.Header>
                                <Accordion.Body>
                                    <Row>
                                        <Col md={6}>
                                            <h6>File Information</h6>
                                            <Table size="sm">
                                                <tbody>
                                                    <tr>
                                                        <td>Type:</td>
                                                        <td>{attachment.content_type}</td>
                                                    </tr>
                                                    <tr>
                                                        <td>Size:</td>
                                                        <td>{(attachment.size / 1024).toFixed(2)} KB</td>
                                                    </tr>
                                                    <tr>
                                                        <td>Status:</td>
                                                        <td>
                                                            <Badge bg={attachment.is_malicious ? 'danger' : 'success'}>
                                                                {attachment.status}
                                                            </Badge>
                                                        </td>
                                                    </tr>
                                                </tbody>
                                            </Table>
                                        </Col>
                                        <Col md={6}>
                                            <h6>File Hashes</h6>
                                            <Table size="sm">
                                                <tbody>
                                                    <tr>
                                                        <td>MD5:</td>
                                                        <td><code>{attachment.hashes.md5}</code></td>
                                                    </tr>
                                                    <tr>
                                                        <td>SHA1:</td>
                                                        <td><code>{attachment.hashes.sha1}</code></td>
                                                    </tr>
                                                    <tr>
                                                        <td>SHA256:</td>
                                                        <td><code>{attachment.hashes.sha256}</code></td>
                                                    </tr>
                                                </tbody>
                                            </Table>
                                        </Col>
                                    </Row>
                                    <h6 className="mt-3">Platform Analysis</h6>
                                    <Accordion>
                                        {Object.entries(attachment.analysis).map(([platform, analysis], pIndex) => (
                                            <Accordion.Item eventKey={pIndex} key={platform}>
                                                <Accordion.Header>
                                                    {platform.toUpperCase()}
                                                </Accordion.Header>
                                                <Accordion.Body>
                                                    <pre className="bg-light p-3 rounded">
                                                        {JSON.stringify(analysis, null, 2)}
                                                    </pre>
                                                </Accordion.Body>
                                            </Accordion.Item>
                                        ))}
                                    </Accordion>
                                </Accordion.Body>
                            </Accordion.Item>
                        ))}
                    </Accordion>
                )}
            </Card.Body>
        </Card>
    );
};

const EmailAnalysisResults = ({ results }) => {
    if (!results) {
        return <Alert variant="info">No analysis results available</Alert>;
    }

    const {
        basic_info,
        authentication,
        ip_analysis,
        url_analysis,
        attachment_analysis,
        threat_score,
        confidence_score,
        risk_indicators
    } = results;

    return (
        <div className="email-analysis-results">
            <Card className="mb-4">
                <Card.Header>
                    <h5 className="card-title mb-0">Analysis Summary</h5>
                </Card.Header>
                <Card.Body>
                    <div className="d-flex justify-content-between align-items-center mb-3">
                        <div>
                            <ThreatBadge score={threat_score} />
                            <ConfidenceBadge score={confidence_score} />
                        </div>
                        <Badge 
                            bg={risk_indicators.color} 
                            className="fs-6"
                        >
                            {risk_indicators.message}
                        </Badge>
                    </div>
                    <Table responsive>
                        <tbody>
                            <tr>
                                <td><strong>From:</strong></td>
                                <td>{basic_info.from}</td>
                            </tr>
                            <tr>
                                <td><strong>To:</strong></td>
                                <td>{basic_info.to}</td>
                            </tr>
                            <tr>
                                <td><strong>Subject:</strong></td>
                                <td>{basic_info.subject}</td>
                            </tr>
                            <tr>
                                <td><strong>Date:</strong></td>
                                <td>{basic_info.date}</td>
                            </tr>
                        </tbody>
                    </Table>
                </Card.Body>
            </Card>

            <AuthenticationResults auth={authentication} />
            <IPAnalysis ipAnalysis={ip_analysis} />
            <URLAnalysis urlAnalysis={url_analysis} />
            <AttachmentAnalysis attachmentAnalysis={attachment_analysis} />
        </div>
    );
};

export default EmailAnalysisResults;
