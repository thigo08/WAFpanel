package org.owasp.esapi.waf.rules.support;

import java.io.InputStream;

import javax.faces.bean.ManagedBean;
import javax.faces.context.FacesContext;
import javax.servlet.ServletContext;

import org.primefaces.model.DefaultStreamedContent;
import org.primefaces.model.StreamedContent;
 
@ManagedBean
public class FileDownloadView {
     
    private StreamedContent file;
     
    public FileDownloadView() {        
        InputStream stream = ((ServletContext)FacesContext.getCurrentInstance().getExternalContext().getContext()).getResourceAsStream("/resources/images/manual.pdf");
        file = new DefaultStreamedContent(stream, "file/pdf", "manual.pdf");
    }
 
    public StreamedContent getFile() {
        return file;
    }
}
