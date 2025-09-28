# Section 5 Artifact Generation

This folder contains the materials to generate the numbers
included in the section 5, table 5 and table 6.

## Dataset

We cannot share the measurements or results that datasets
There are use in the jupyter Notebook Measurement Analysis.

The jupyter notebook produce two file :
- generated/LaTexData.json
- step_with_fixes.csv

Those files are needed to run the jupyter notebook "Latex Number Generation"

## Generate the LaTex Number

Run the jupyter notebook.
This notebook will produce the file DynamicNumbers.tex and table-6.tex.
Those are the actual file we use in to produce the paper.



## Generate the pdf

We provided "output.tex" that generates the pdf containing
table 5 and table 6.

Table 6 is completely generated from the jupyter notebook
Table 5 embed some LaTeX command such as `\DfixerDynamicNbJsonFileOnlyHavingNNSIC`
This command is defined in the file generated/DynamicNumbers.tex


To generate output.pdf, run 
```python
pdflatex output.tex
```